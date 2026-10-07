#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { WeddingStack } from '../lib/wedding-stack';

const app = new cdk.App();

const passwordHash = process.env.PASSWORD_HASH;
const cookieSecret = process.env.COOKIE_SECRET;
const githubRepo = process.env.GITHUB_REPO ?? 'christopherheneghan/wedding_site';

if (!passwordHash) {
  throw new Error(
    'PASSWORD_HASH is required.\n' +
    'Generate it with: node -e "const c=require(\'crypto\');' +
    'console.log(c.createHash(\'sha256\').update(\'YOUR_PASSWORD\').digest(\'hex\'))"',
  );
}

if (!cookieSecret) {
  throw new Error(
    'COOKIE_SECRET is required.\n' +
    'Generate it with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
  );
}

new WeddingStack(app, 'WeddingSite', {
  passwordHash,
  cookieSecret,
  githubRepo,
  env: {
    // Lambda@Edge and ACM certs for CloudFront must be in us-east-1
    region: 'us-east-1',
    account: process.env.CDK_DEFAULT_ACCOUNT ?? process.env.AWS_ACCOUNT_ID,
  },
});
