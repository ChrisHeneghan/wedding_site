import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

interface WeddingStackProps extends cdk.StackProps {
  passwordHash: string;
  cookieSecret: string;
  githubRepo: string; // e.g. "christopherheneghan/wedding_site"
}

export class WeddingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: WeddingStackProps) {
    super(scope, id, props);

    // ── S3 bucket — private, no public access ──
    const siteBucket = new s3.Bucket(this, 'SiteBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.RETAIN, // don't delete content on cdk destroy
    });

    // ── ACM certificate — must be us-east-1 for CloudFront ──
    // CDK will print the DNS validation CNAME records to add in Cloudflare.
    // The deploy will wait (up to 30 min) until the cert is issued.
    const cert = new acm.Certificate(this, 'Certificate', {
      domainName: 'morgan-chris.com',
      subjectAlternativeNames: ['www.morgan-chris.com'],
      validation: acm.CertificateValidation.fromDns(),
    });

    // ── Lambda@Edge auth function ──
    // Lambda@Edge does not support env vars, so hash/secret are substituted at synth time.
    // Code.fromInline() has a 4096-byte CloudFormation limit — write to a temp dir instead.
    const authSourceCode = readFileSync(join(__dirname, '../../edge/auth.js'), 'utf-8')
      .replace(/__PASSWORD_HASH__/g, props.passwordHash)
      .replace(/__COOKIE_SECRET__/g, props.cookieSecret);

    const edgeTmpDir = join(tmpdir(), 'wedding-edge-fn');
    mkdirSync(edgeTmpDir, { recursive: true });
    writeFileSync(join(edgeTmpDir, 'auth.js'), authSourceCode);

    // experimental.EdgeFunction ensures the function is deployed in us-east-1
    const authFn = new cloudfront.experimental.EdgeFunction(this, 'AuthFn', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'auth.handler',
      code: lambda.Code.fromAsset(edgeTmpDir),
      description: 'Wedding site password gate',
    });


    // ── CloudFront distribution ──
    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(siteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL, // POST /login requires this
        edgeLambdas: [
          {
            functionVersion: authFn.currentVersion,
            eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
            includeBody: true, // required to read POST /login body
          },
        ],
      },
      domainNames: ['morgan-chris.com', 'www.morgan-chris.com'],
      certificate: cert,
      defaultRootObject: 'index.html',
      // S3 returns 403 for missing paths — remap to login page
      errorResponses: [
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: '/login/index.html',
          ttl: cdk.Duration.seconds(0),
        },
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: '/login/index.html',
          ttl: cdk.Duration.seconds(0),
        },
      ],
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
    });

    // ── GitHub Actions OIDC deploy role ──
    const githubProvider = new iam.OpenIdConnectProvider(this, 'GithubOidcProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com'],
      thumbprints: ['6938fd4d98bab03faadb97b34396831e3780aea1'],
    });

    const deployRole = new iam.Role(this, 'DeployRole', {
      roleName: 'wedding-site-deploy',
      assumedBy: new iam.FederatedPrincipal(
        githubProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          },
          StringLike: {
            'token.actions.githubusercontent.com:sub':
              `repo:${props.githubRepo}:ref:refs/heads/main`,
          },
        },
        'sts:AssumeRoleWithWebIdentity',
      ),
    });

    deployRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['s3:PutObject', 's3:DeleteObject', 's3:ListBucket'],
        resources: [siteBucket.bucketArn, `${siteBucket.bucketArn}/*`],
      }),
    );

    deployRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['cloudfront:CreateInvalidation'],
        resources: [
          `arn:aws:cloudfront::${this.account}:distribution/${distribution.distributionId}`,
        ],
      }),
    );

    // ── Outputs — copy these into GitHub Actions secrets ──
    new cdk.CfnOutput(this, 'BucketName', {
      value: siteBucket.bucketName,
      description: 'Set as S3_BUCKET in GitHub Actions secrets',
    });
    new cdk.CfnOutput(this, 'DistributionId', {
      value: distribution.distributionId,
      description: 'Set as CF_DISTRIBUTION_ID in GitHub Actions secrets',
    });
    new cdk.CfnOutput(this, 'DistributionDomain', {
      value: distribution.distributionDomainName,
      description: 'Add as CNAME target in Cloudflare DNS',
    });
    new cdk.CfnOutput(this, 'DeployRoleArn', {
      value: deployRole.roleArn,
      description: 'Set as AWS_DEPLOY_ROLE_ARN in GitHub Actions secrets',
    });
  }
}
