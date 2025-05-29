import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { promisify } from 'util';

// Initialize Express app
const app = express();

// Middleware to parse JSON payloads
app.use(express.json({ limit: '10mb' }));

// Define the port - Railway will set PORT environment variable
const PORT = process.env.PORT || 3000;

// Get webhook secrets from environment variables
const WEBHOOK_SECRETS = {
  'order-created': process.env.WC_ORDER_CREATED_SECRET || '',
  'order-updated': process.env.WC_ORDER_UPDATED_SECRET || ''
};

// Create a directory for payload examples
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);
const existsAsync = promisify(fs.exists);

// Ensure payloads directory exists
const PAYLOADS_DIR = path.join(__dirname, '..', 'example-payloads');

async function ensureDirectoryExists(): Promise<void> {
  try {
    const exists = await existsAsync(PAYLOADS_DIR);
    if (!exists) {
      await mkdirAsync(PAYLOADS_DIR, { recursive: true });
      console.log(`Created payloads directory at ${PAYLOADS_DIR}`);
    }
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error ensuring directory exists: ${err.message}`);
  }
}

// Create directory on startup
void ensureDirectoryExists();

// Middleware to validate webhook signatures
const validateWebhookSignature = (webhookType: 'order-created' | 'order-updated') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const signature = req.headers['x-wc-webhook-signature'] as string;
    const secret = WEBHOOK_SECRETS[webhookType];
    
    // If no secret is set, skip validation
    if (!secret) {
      console.log(`No secret configured for ${webhookType}, skipping validation`);
      next();
      return;
    }

    // If signature is missing, reject
    if (!signature) {
      console.error('Webhook signature header missing');
      res.status(401).send('Webhook signature missing');
      return;
    }

    try {
      const payload = JSON.stringify(req.body);
      const hmac = crypto.createHmac('sha256', secret);
      const digest = hmac.update(payload).digest('base64');
      
      // Compare the calculated signature with the one in the header
      if (signature === digest) {
        console.log('Webhook signature validated successfully');
        next();
      } else {
        console.error('Webhook signature validation failed');
        res.status(401).send('Invalid webhook signature');
      }
    } catch (error: unknown) {
      const err = error as Error;
      console.error('Error validating webhook signature:', err.message);
      res.status(500).send('Error processing webhook');
    }
  };
};

// Create order.created webhook endpoint
app.post('/webhooks/woocommerce/order-created', validateWebhookSignature('order-created'), async (req: Request, res: Response): Promise<void> => {
  const logTimestamp = new Date().toISOString();
  console.log(`[${logTimestamp}] Received order.created webhook.`);
  
  const payload = req.body;
  
  // Write the payload to the example-payloads directory with timestamp
  const fileTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `order_created_${fileTimestamp}.json`;
  
  try {
    await writeFileAsync(
      path.join(PAYLOADS_DIR, filename),
      JSON.stringify(payload, null, 2)
    );
    console.log(`Successfully wrote ${filename}`);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error writing payload file: ${err.message}`);
  }
  
  // Send success response
  res.status(200).send('Webhook received');
});

// Create order.updated webhook endpoint
app.post('/webhooks/woocommerce/order-updated', validateWebhookSignature('order-updated'), async (req: Request, res: Response): Promise<void> => {
  const logTimestamp = new Date().toISOString();
  console.log(`[${logTimestamp}] Received order.updated webhook.`);
  
  const payload = req.body;
  
  // Write the payload to the example-payloads directory with timestamp
  const fileTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `order_updated_${fileTimestamp}.json`;
  
  try {
    await writeFileAsync(
      path.join(PAYLOADS_DIR, filename),
      JSON.stringify(payload, null, 2)
    );
    console.log(`Successfully wrote ${filename}`);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error writing payload file: ${err.message}`);
  }
  
  // Send success response
  res.status(200).send('Webhook received');
});

// Basic error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction): void => {
  console.error(`Error: ${err.message}`);
  res.status(500).send('Internal Server Error');
});

// Add a health check endpoint for Railway
app.get('/', (req: Request, res: Response): void => {
  res.status(200).send({
    status: 'ok',
    service: 'WooCommerce Webhook Receiver',
    endpoints: [
      '/webhooks/woocommerce/order-created',
      '/webhooks/woocommerce/order-updated'
    ]
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Webhook endpoints:`);
  console.log(`- POST /webhooks/woocommerce/order-created`);
  console.log(`- POST /webhooks/woocommerce/order-updated`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Secret for order-created configured: ${Boolean(WEBHOOK_SECRETS['order-created'])}`);
  console.log(`Secret for order-updated configured: ${Boolean(WEBHOOK_SECRETS['order-updated'])}`);
});
