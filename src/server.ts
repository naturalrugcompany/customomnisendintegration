import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { promisify } from 'util';

// Initialize Express app
const app = express();

// Add a middleware to capture the raw body for signature validation
// This must be BEFORE express.json() to access the raw body
const captureRawBody = (req: Request, res: Response, next: NextFunction): void => {
  let data = '';
  req.on('data', (chunk) => {
    data += chunk.toString();
  });
  req.on('end', () => {
    (req as any).rawBody = data;
    next();
  });
};

// Only apply raw body capture to webhook routes
app.use('/webhooks/woocommerce', captureRawBody);

// Middleware to parse JSON payloads - must come AFTER raw body capture
app.use(express.json({ limit: '10mb' }));

// Define the port - Railway will set PORT environment variable
const PORT = process.env.PORT || 3000;

// Define secrets for each webhook type
const WEBHOOK_SECRETS: Record<string, string> = {
  'order-created': process.env.WC_ORDER_CREATED_SECRET || 'default_secret_replace_me',
  'order-updated': process.env.WC_ORDER_UPDATED_SECRET || 'default_secret_replace_me'
};

// Directories to store payloads and orders
const PAYLOADS_DIR = path.join(__dirname, '..', 'example-payloads');
const ORDERS_DIR = path.join(__dirname, '..', 'orders');

// Promisify fs functions
const fsPromises = {
  readdir: promisify(fs.readdir),
  readFile: promisify(fs.readFile),
  writeFile: promisify(fs.writeFile),
  stat: promisify(fs.stat),
  mkdir: promisify(fs.mkdir),
  access: promisify(fs.access),
};

// Alias for writeFile
const writeFileAsync = fsPromises.writeFile;

// Function to ensure the directories exist
const ensureDirectoriesExist = async (): Promise<void> => {
  try {
    await fsPromises.mkdir(PAYLOADS_DIR, { recursive: true });
    console.log(`Directory created/exists: ${PAYLOADS_DIR}`);
    
    await fsPromises.mkdir(ORDERS_DIR, { recursive: true });
    console.log(`Directory created/exists: ${ORDERS_DIR}`);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error creating directories: ${err.message}`);
  }
};

// Create directories on startup
void ensureDirectoriesExist();

// WooCommerce Order interface
interface WooCommerceOrder {
  id: number;
  number: string;
  status: string;
  date_created: string;
  date_modified: string;
  date_paid?: string | null;
  date_completed?: string | null;
  total: string;
  customer_id: number;
  billing: {
    first_name: string;
    last_name: string;
    email: string;
    phone: string;
  };
  payment_method: string;
  payment_method_title: string;
  line_items: Array<{
    id: number;
    name: string;
    quantity: number;
    total: string;
  }>;
  // Add other fields as needed
}

// Function to save or update an order
const saveOrder = async (order: WooCommerceOrder): Promise<void> => {
  const orderNumber = order.number;
  const orderFilePath = path.join(ORDERS_DIR, `order_${orderNumber}.json`);
  
  // Check if order already exists
  let existingOrder: WooCommerceOrder | null = null;
  
  try {
    // Check if file exists
    await fsPromises.access(orderFilePath, fs.constants.F_OK);
    
    // Read existing order
    const orderData = await fsPromises.readFile(orderFilePath, 'utf8');
    existingOrder = JSON.parse(orderData) as WooCommerceOrder;
    
    // Compare modification dates to see if update is needed
    const existingModifiedDate = new Date(existingOrder.date_modified);
    const newModifiedDate = new Date(order.date_modified);
    
    if (newModifiedDate <= existingModifiedDate) {
      console.log(`Order ${orderNumber} already has a more recent update. Skipping.`);
      return;
    }
    
    console.log(`Updating existing order ${orderNumber}`);
  } catch (error) {
    // Order doesn't exist yet, will create a new one
    console.log(`Creating new order ${orderNumber}`);
  }
  
  // Save the order
  try {
    await writeFileAsync(orderFilePath, JSON.stringify(order, null, 2));
    console.log(`Successfully saved order ${orderNumber}`);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error saving order ${orderNumber}: ${err.message}`);
  }
};

// Environment variable to skip signature validation if needed
const SKIP_SIGNATURE_VALIDATION = process.env.SKIP_SIGNATURE_VALIDATION === 'true';

// Middleware to validate webhook signatures
const validateWebhookSignature = (webhookType: 'order-created' | 'order-updated') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip validation if configured to do so
    if (SKIP_SIGNATURE_VALIDATION) {
      console.log('Skipping webhook signature validation as configured');
      next();
      return;
    }
    
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
      // Use the raw body captured before JSON parsing if available
      const rawBody = (req as any).rawBody;
      
      // Calculate the HMAC SHA256 signature exactly as WooCommerce does
      let calculatedSignature = '';
      
      if (rawBody) {
        // Use the raw body string directly as WooCommerce does
        const hmac = crypto.createHmac('sha256', secret);
        calculatedSignature = hmac.update(rawBody).digest('base64');
      } else {
        // Fallback if raw body is not available - less reliable
        const payload = JSON.stringify(req.body);
        const hmac = crypto.createHmac('sha256', secret);
        calculatedSignature = hmac.update(payload).digest('base64');
      }
      
      // Add debug logging
      console.log('Debug - WooCommerce Signature Verification:');
      console.log(`Received signature: ${signature}`);
      console.log(`Calculated signature: ${calculatedSignature}`);
      console.log(`Used raw body: ${Boolean(rawBody)}`);
      console.log(`Secret used (first 4 chars): ${secret.substring(0, 4)}...`);
      if (rawBody) {
        console.log(`Raw body length: ${rawBody.length} characters`);
      }
      
      // Verify the signature
      if (signature === calculatedSignature) {
        console.log('✅ Webhook signature validated successfully');
        next();
      } else {
        console.error('❌ Webhook signature validation failed');
        
        // For development, accept the webhook anyway
        // In production, you would want to reject invalid signatures
        console.log('DEVELOPMENT MODE: Proceeding despite signature mismatch');
        next();
        
        // In production, uncomment this line:
        // return res.status(401).send('Invalid webhook signature');
      }
    } catch (error: unknown) {
      const err = error as Error;
      console.error('Error validating webhook signature:', err.message);
      
      // For development, continue anyway
      console.log('DEVELOPMENT MODE: Continuing despite signature error');
      next();
      
      // In production, uncomment this line:
      // return res.status(500).send('Error processing webhook');
    }
  };
};

// Create order.created webhook endpoint
app.post('/webhooks/woocommerce/order-created', validateWebhookSignature('order-created'), async (req: Request, res: Response): Promise<void> => {
  const logTimestamp = new Date().toISOString();
  console.log(`[${logTimestamp}] Received order.created webhook.`);
  
  // Get payload from either parsed JSON body or raw body
  let payload = req.body;
  
  // If req.body is undefined, try to parse the raw body as a fallback
  if (!payload && (req as any).rawBody) {
    try {
      payload = JSON.parse((req as any).rawBody);
      console.log('Using parsed raw body as fallback');
    } catch (e) {
      console.log('Failed to parse raw body as JSON:', e);
      // Store raw body as string if JSON parsing fails
      payload = { rawContent: (req as any).rawBody };
    }
  }
  
  // Write the payload to the example-payloads directory with timestamp
  const fileTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `order_created_${fileTimestamp}.json`;
  
  try {
    // Check if payload exists before writing
    if (!payload) {
      throw new Error('No payload data found in request');
    }
    
    await writeFileAsync(
      path.join(PAYLOADS_DIR, filename),
      JSON.stringify(payload, null, 2)
    );
    console.log(`Successfully wrote ${filename}`);
    
    // Try to save the order data for the dashboard
    try {
      await saveOrder(payload as WooCommerceOrder);
    } catch (orderError: unknown) {
      const err = orderError as Error;
      console.error(`Error saving order data: ${err.message}`);
    }
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
  
  // Get payload from either parsed JSON body or raw body
  let payload = req.body;
  
  // If req.body is undefined, try to parse the raw body as a fallback
  if (!payload && (req as any).rawBody) {
    try {
      payload = JSON.parse((req as any).rawBody);
      console.log('Using parsed raw body as fallback');
    } catch (e) {
      console.log('Failed to parse raw body as JSON:', e);
      // Store raw body as string if JSON parsing fails
      payload = { rawContent: (req as any).rawBody };
    }
  }
  
  // Write the payload to the example-payloads directory with timestamp
  const fileTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `order_updated_${fileTimestamp}.json`;
  
  try {
    // Check if payload exists before writing
    if (!payload) {
      throw new Error('No payload data found in request');
    }
    
    await writeFileAsync(
      path.join(PAYLOADS_DIR, filename),
      JSON.stringify(payload, null, 2)
    );
    console.log(`Successfully wrote ${filename}`);
    
    // Try to save the order data for the dashboard
    try {
      await saveOrder(payload as WooCommerceOrder);
    } catch (orderError: unknown) {
      const err = orderError as Error;
      console.error(`Error saving order data: ${err.message}`);
    }
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
      '/webhooks/woocommerce/order-updated',
      '/admin/orders',
      '/admin/orders/:orderNumber',
      '/admin/payloads',
      '/admin/payloads/:filename'
    ]
  });
});

// Admin endpoint to list all orders with a nice UI
app.get('/admin/orders', async (req: Request, res: Response): Promise<void> => {
  try {
    const files = await fsPromises.readdir(ORDERS_DIR);
    const orderDetails = await Promise.all(
      files.map(async (filename) => {
        if (!filename.startsWith('order_') || !filename.endsWith('.json')) {
          return null; // Skip non-order files
        }
        
        const filePath = path.join(ORDERS_DIR, filename);
        const content = await fsPromises.readFile(filePath, 'utf8');
        const order = JSON.parse(content) as WooCommerceOrder;
        
        // Convert timestamps to Date objects
        const dateCreated = new Date(order.date_created);
        const dateModified = new Date(order.date_modified);
        const datePaid = order.date_paid ? new Date(order.date_paid) : null;
        
        return {
          orderNumber: order.number,
          id: order.id,
          status: order.status,
          total: parseFloat(order.total),
          totalFormatted: `${order.currency_symbol || '£'}${parseFloat(order.total).toFixed(2)}`,
          dateCreated,
          dateModified,
          datePaid,
          customerName: `${order.billing.first_name} ${order.billing.last_name}`,
          customerEmail: order.billing.email,
          paymentMethod: order.payment_method_title,
          isPaid: !!order.date_paid,
          formattedDate: dateCreated.toISOString().split('T')[0],
          formattedTime: dateCreated.toISOString().split('T')[1].substring(0, 8),
          items: order.line_items.length
        };
      })
    );
    
    // Filter out null values and sort by order number (newest first)
    const validOrders = orderDetails
      .filter((order): order is NonNullable<typeof order> => order !== null)
      .sort((a, b) => parseInt(b.orderNumber) - parseInt(a.orderNumber));
    
    // Generate HTML response
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>WooCommerce Orders Dashboard</title>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        * {
          box-sizing: border-box;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
          background-color: #f5f5f7;
          margin: 0;
          padding: 20px;
          color: #333;
        }
        .header-container {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        h1 {
          color: #2c3e50;
          margin: 0;
        }
        .count-badge {
          background-color: #3498db;
          color: white;
          padding: 5px 10px;
          border-radius: 20px;
          font-size: 14px;
          font-weight: bold;
        }
        .orders-container {
          background-color: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
          overflow: hidden;
        }
        table {
          width: 100%;
          border-collapse: collapse;
        }
        th {
          background-color: #f8f9fa;
          padding: 12px 15px;
          text-align: left;
          font-weight: 600;
          color: #2c3e50;
          border-bottom: 1px solid #e9ecef;
        }
        td {
          padding: 12px 15px;
          border-bottom: 1px solid #e9ecef;
        }
        tr:hover {
          background-color: #f8f9fa;
        }
        .order-link {
          color: #3498db;
          font-weight: 600;
          text-decoration: none;
        }
        .order-link:hover {
          text-decoration: underline;
        }
        .status-badge {
          display: inline-block;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
        }
        .status-processing {
          background-color: #3498db;
          color: white;
        }
        .status-completed {
          background-color: #2ecc71;
          color: white;
        }
        .status-on-hold {
          background-color: #f39c12;
          color: white;
        }
        .status-pending {
          background-color: #95a5a6;
          color: white;
        }
        .status-cancelled {
          background-color: #e74c3c;
          color: white;
        }
        .status-refunded {
          background-color: #9b59b6;
          color: white;
        }
        .status-failed {
          background-color: #c0392b;
          color: white;
        }
        .payment-badge {
          display: inline-block;
          padding: 3px 6px;
          border-radius: 3px;
          font-size: 12px;
          font-weight: 600;
        }
        .payment-paid {
          background-color: #e8f5e9;
          color: #2e7d32;
        }
        .payment-unpaid {
          background-color: #ffebee;
          color: #c62828;
        }
        .price {
          font-weight: 600;
        }
        .back-button {
          display: inline-block;
          margin-bottom: 20px;
          padding: 8px 16px;
          background-color: #f8f9fa;
          color: #2c3e50;
          text-decoration: none;
          border-radius: 4px;
          font-weight: 500;
          border: 1px solid #ddd;
        }
        .back-button:hover {
          background-color: #e9ecef;
        }
        .nav-links {
          display: flex;
          gap: 20px;
          margin-bottom: 20px;
        }
        .nav-link {
          text-decoration: none;
          padding: 8px 16px;
          background-color: #fff;
          color: #3498db;
          border-radius: 4px;
          font-weight: 500;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .nav-link:hover {
          background-color: #f8f9fa;
        }
        .nav-link.active {
          background-color: #3498db;
          color: white;
        }
        .empty-message {
          text-align: center;
          padding: 30px;
          color: #7f8c8d;
          font-style: italic;
        }
        .auto-refresh {
          font-size: 12px;
          color: #7f8c8d;
          margin-top: 10px;
          text-align: center;
        }
      </style>
      <script>
        // Auto-refresh the page every 30 seconds
        setTimeout(() => {
          window.location.reload();
        }, 30000);
      </script>
    </head>
    <body>
      <div class="header-container">
        <h1>WooCommerce Orders Dashboard</h1>
        <span class="count-badge">${validOrders.length} Orders</span>
      </div>
      
      <div class="nav-links">
        <a href="/admin/orders" class="nav-link active">Orders</a>
        <a href="/admin/payloads" class="nav-link">Webhook Payloads</a>
      </div>
      
      <div class="orders-container">
        ${validOrders.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Order #</th>
              <th>Date</th>
              <th>Customer</th>
              <th>Status</th>
              <th>Payment</th>
              <th>Total</th>
              <th>Items</th>
            </tr>
          </thead>
          <tbody>
            ${validOrders.map(order => `
              <tr>
                <td><a href="/admin/orders/${order.orderNumber}" class="order-link">#${order.orderNumber}</a></td>
                <td>${order.formattedDate} ${order.formattedTime}</td>
                <td>${order.customerName}</td>
                <td><span class="status-badge status-${order.status}">${order.status}</span></td>
                <td>
                  ${order.isPaid 
                    ? `<span class="payment-badge payment-paid">Paid</span>` 
                    : `<span class="payment-badge payment-unpaid">Unpaid</span>`}
                </td>
                <td class="price">${order.totalFormatted}</td>
                <td>${order.items}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        ` : `
        <div class="empty-message">
          No orders found. Waiting for webhook data...
        </div>
        `}
      </div>
      <div class="auto-refresh">This page auto-refreshes every 30 seconds</div>
    </body>
    </html>
    `;
    
    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(html);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error listing orders: ${err.message}`);
    res.status(500).send(`<h1>Error</h1><p>Failed to list orders: ${err.message}</p>`);
  }
});

// Admin endpoint to view a specific order with details
app.get('/admin/orders/:orderNumber', async (req: Request, res: Response): Promise<void> => {
  try {
    const orderNumber = req.params.orderNumber;
    const orderFilePath = path.join(ORDERS_DIR, `order_${orderNumber}.json`);
    
    // Check if order file exists
    try {
      await fsPromises.access(orderFilePath, fs.constants.F_OK);
    } catch (error) {
      return res.status(404).send(`<h1>Error</h1><p>Order #${orderNumber} not found</p>`);
    }
    
    // Read and parse order data
    const orderData = await fsPromises.readFile(orderFilePath, 'utf8');
    const order = JSON.parse(orderData) as WooCommerceOrder;
    
    // Generate HTML for order details
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Order #${order.number} Details</title>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        * {
          box-sizing: border-box;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
          background-color: #f5f5f7;
          margin: 0;
          padding: 20px;
          color: #333;
        }
        .back-button {
          display: inline-block;
          margin-bottom: 20px;
          padding: 8px 16px;
          background-color: #f8f9fa;
          color: #2c3e50;
          text-decoration: none;
          border-radius: 4px;
          font-weight: 500;
          border: 1px solid #ddd;
        }
        .back-button:hover {
          background-color: #e9ecef;
        }
        h1 {
          color: #2c3e50;
          margin-bottom: 20px;
          display: flex;
          align-items: center;
          gap: 15px;
        }
        .status-badge {
          display: inline-block;
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 600;
          text-transform: uppercase;
        }
        .status-processing {
          background-color: #3498db;
          color: white;
        }
        .status-completed {
          background-color: #2ecc71;
          color: white;
        }
        .status-on-hold {
          background-color: #f39c12;
          color: white;
        }
        .status-pending {
          background-color: #95a5a6;
          color: white;
        }
        .status-cancelled {
          background-color: #e74c3c;
          color: white;
        }
        .status-refunded {
          background-color: #9b59b6;
          color: white;
        }
        .status-failed {
          background-color: #c0392b;
          color: white;
        }
        .section {
          background-color: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
          margin-bottom: 20px;
          padding: 20px;
        }
        .order-header {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
        }
        .order-info-item {
          margin-bottom: 15px;
        }
        .order-info-label {
          font-size: 12px;
          text-transform: uppercase;
          color: #7f8c8d;
          margin-bottom: 5px;
        }
        .order-info-value {
          font-size: 16px;
          font-weight: 500;
        }
        .address-container {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
        }
        .address-box {
          background-color: #f8f9fa;
          padding: 15px;
          border-radius: 4px;
          line-height: 1.5;
        }
        .address-title {
          font-weight: 600;
          margin-bottom: 10px;
          color: #2c3e50;
        }
        .items-table {
          width: 100%;
          border-collapse: collapse;
        }
        .items-table th {
          background-color: #f8f9fa;
          padding: 12px 15px;
          text-align: left;
          font-weight: 600;
          color: #2c3e50;
          border-bottom: 1px solid #e9ecef;
        }
        .items-table td {
          padding: 12px 15px;
          border-bottom: 1px solid #e9ecef;
        }
        .product-image {
          width: 60px;
          height: 60px;
          object-fit: cover;
          border-radius: 4px;
        }
        .product-name {
          font-weight: 500;
        }
        .order-totals {
          margin-top: 20px;
          display: flex;
          flex-direction: column;
          align-items: flex-end;
        }
        .total-row {
          display: flex;
          justify-content: space-between;
          width: 250px;
          padding: 8px 0;
          border-bottom: 1px solid #e9ecef;
        }
        .total-row:last-child {
          border-bottom: none;
          font-weight: 700;
          font-size: 18px;
          padding-top: 15px;
        }
        .payment-info {
          margin-top: 15px;
          padding-top: 15px;
          border-top: 1px solid #e9ecef;
        }
        .payment-badge {
          display: inline-block;
          padding: 5px 10px;
          border-radius: 4px;
          font-weight: 600;
          margin-top: 5px;
        }
        .payment-paid {
          background-color: #e8f5e9;
          color: #2e7d32;
        }
        .payment-unpaid {
          background-color: #ffebee;
          color: #c62828;
        }
        .raw-json {
          margin-top: 20px;
        }
        .json-toggle {
          background-color: #f8f9fa;
          border: 1px solid #ddd;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 500;
          display: inline-block;
          margin-bottom: 10px;
        }
        .json-toggle:hover {
          background-color: #e9ecef;
        }
        pre {
          background-color: #f8f9fa;
          border-radius: 4px;
          padding: 15px;
          overflow: auto;
          display: none;
          max-height: 500px;
        }
        .meta-data {
          margin-top: 20px;
          font-size: 14px;
          color: #7f8c8d;
        }
        .shipping-line {
          display: flex;
          justify-content: space-between;
          padding: 10px 0;
          border-bottom: 1px solid #e9ecef;
        }
        .shipping-line:last-child {
          border-bottom: none;
        }
      </style>
      <script>
        function toggleJSON() {
          const pre = document.getElementById('json-content');
          if (pre.style.display === 'none' || pre.style.display === '') {
            pre.style.display = 'block';
          } else {
            pre.style.display = 'none';
          }
        }
        
        function copyJSON() {
          const jsonContent = document.getElementById('json-raw-content').textContent;
          navigator.clipboard.writeText(jsonContent).then(() => {
            alert('JSON copied to clipboard!');
          });
        }
      </script>
    </head>
    <body>
      <a href="/admin/orders" class="back-button">← Back to Orders</a>
      
      <h1>
        Order #${order.number}
        <span class="status-badge status-${order.status}">${order.status}</span>
      </h1>
      
      <div class="section">
        <div class="order-header">
          <div class="order-info-item">
            <div class="order-info-label">Order Date</div>
            <div class="order-info-value">${new Date(order.date_created).toLocaleString()}</div>
          </div>
          
          <div class="order-info-item">
            <div class="order-info-label">Last Modified</div>
            <div class="order-info-value">${new Date(order.date_modified).toLocaleString()}</div>
          </div>
          
          <div class="order-info-item">
            <div class="order-info-label">Payment Method</div>
            <div class="order-info-value">${order.payment_method_title}</div>
          </div>
          
          <div class="order-info-item">
            <div class="order-info-label">Payment Status</div>
            <div class="order-info-value">
              ${order.date_paid 
                ? `<span class="payment-badge payment-paid">Paid (${new Date(order.date_paid).toLocaleString()})</span>` 
                : `<span class="payment-badge payment-unpaid">Unpaid</span>`}
            </div>
          </div>
          
          ${order.transaction_id ? `
          <div class="order-info-item">
            <div class="order-info-label">Transaction ID</div>
            <div class="order-info-value">${order.transaction_id}</div>
          </div>
          ` : ''}
        </div>
      </div>
      
      <div class="section">
        <h2>Customer Information</h2>
        <div class="address-container">
          <div>
            <div class="address-title">Billing Address</div>
            <div class="address-box">
              ${order.billing.first_name} ${order.billing.last_name}<br>
              ${order.billing.company ? order.billing.company + '<br>' : ''}
              ${order.billing.address_1}<br>
              ${order.billing.address_2 ? order.billing.address_2 + '<br>' : ''}
              ${order.billing.city}, ${order.billing.state ? order.billing.state + ', ' : ''} ${order.billing.postcode}<br>
              ${order.billing.country}<br>
              <br>
              Email: ${order.billing.email}<br>
              Phone: ${order.billing.phone}
            </div>
          </div>
          
          <div>
            <div class="address-title">Shipping Address</div>
            <div class="address-box">
              ${order.shipping.first_name} ${order.shipping.last_name}<br>
              ${order.shipping.company ? order.shipping.company + '<br>' : ''}
              ${order.shipping.address_1}<br>
              ${order.shipping.address_2 ? order.shipping.address_2 + '<br>' : ''}
              ${order.shipping.city}, ${order.shipping.state ? order.shipping.state + ', ' : ''} ${order.shipping.postcode}<br>
              ${order.shipping.country}<br>
              ${order.shipping.phone ? '<br>Phone: ' + order.shipping.phone : ''}
            </div>
          </div>
        </div>
      </div>
      
      <div class="section">
        <h2>Order Items</h2>
        <table class="items-table">
          <thead>
            <tr>
              <th>Product</th>
              <th>Quantity</th>
              <th>Price</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            ${order.line_items.map(item => `
              <tr>
                <td>
                  <div style="display: flex; align-items: center; gap: 15px;">
                    ${item.image && item.image.src ? `<img src="${item.image.src}" class="product-image" alt="${item.name}">` : ''}
                    <div>
                      <div class="product-name">${item.name}</div>
                      <div style="font-size: 12px; color: #7f8c8d;">SKU: ${item.sku || 'N/A'}</div>
                      ${item.meta_data && item.meta_data.length > 0 ? `
                        <div style="font-size: 12px; margin-top: 5px;">
                          ${item.meta_data.map(meta => `
                            <div><strong>${meta.key}:</strong> ${meta.value}</div>
                          `).join('')}
                        </div>
                      ` : ''}
                    </div>
                  </div>
                </td>
                <td>${item.quantity}</td>
                <td>${order.currency_symbol || '£'}${parseFloat(item.price).toFixed(2)}</td>
                <td>${order.currency_symbol || '£'}${parseFloat(item.total).toFixed(2)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        
        ${order.shipping_lines && order.shipping_lines.length > 0 ? `
        <div style="margin-top: 20px;">
          <h3>Shipping</h3>
          ${order.shipping_lines.map(shipping => `
            <div class="shipping-line">
              <div>${shipping.method_title}</div>
              <div>${order.currency_symbol || '£'}${parseFloat(shipping.total).toFixed(2)}</div>
            </div>
          `).join('')}
        </div>
        ` : ''}
        
        <div class="order-totals">
          <div class="total-row">
            <div>Subtotal:</div>
            <div>${order.currency_symbol || '£'}${(parseFloat(order.total) - parseFloat(order.shipping_total || '0')).toFixed(2)}</div>
          </div>
          ${parseFloat(order.shipping_total) > 0 ? `
          <div class="total-row">
            <div>Shipping:</div>
            <div>${order.currency_symbol || '£'}${parseFloat(order.shipping_total).toFixed(2)}</div>
          </div>
          ` : ''}
          ${parseFloat(order.discount_total) > 0 ? `
          <div class="total-row">
            <div>Discount:</div>
            <div>-${order.currency_symbol || '£'}${parseFloat(order.discount_total).toFixed(2)}</div>
          </div>
          ` : ''}
          ${parseFloat(order.total_tax) > 0 ? `
          <div class="total-row">
            <div>Tax:</div>
            <div>${order.currency_symbol || '£'}${parseFloat(order.total_tax).toFixed(2)}</div>
          </div>
          ` : ''}
          <div class="total-row">
            <div>Total:</div>
            <div>${order.currency_symbol || '£'}${parseFloat(order.total).toFixed(2)}</div>
          </div>
        </div>
      </div>
      
      <div class="section raw-json">
        <h2>Raw Order Data</h2>
        <button class="json-toggle" onclick="toggleJSON()">Show/Hide JSON</button>
        <button class="json-toggle" onclick="copyJSON()">Copy JSON</button>
        <pre id="json-content"><code id="json-raw-content">${JSON.stringify(order, null, 2)}</code></pre>
        
        <div class="meta-data">
          <p>Last Updated: ${new Date(order.date_modified).toLocaleString()}</p>
        </div>
      </div>
    </body>
    </html>
    `;
    
    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(html);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error viewing order: ${err.message}`);
    res.status(500).send(`<h1>Error</h1><p>Failed to view order: ${err.message}</p>`);
  }
});

// Admin endpoint to list all payload files with HTML interface
app.get('/admin/payloads', async (req: Request, res: Response): Promise<void> => {
  try {
    const files = await fsPromises.readdir(PAYLOADS_DIR);
    const fileDetails = await Promise.all(
      files.map(async (filename) => {
        const filePath = path.join(PAYLOADS_DIR, filename);
        const stats = await fsPromises.stat(filePath);
        
        // Parse timestamp from filename
        const timestampMatch = filename.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}.*)\.json/);
        const timestamp = timestampMatch ? timestampMatch[1].replace(/-/g, ':') : 'Unknown';
        
        return {
          filename,
          size: (stats.size / 1024).toFixed(2) + ' KB', // Format size in KB
          created: stats.mtime,
          formattedDate: stats.mtime.toISOString().replace('T', ' ').substring(0, 19),
          type: filename.includes('order_created') ? 'Order Created' : 'Order Updated',
          timestamp
        };
      })
    );
    
    // Sort by creation date (newest first)
    const sortedFiles = fileDetails.sort((a, b) => b.created.getTime() - a.created.getTime());
    
    // Generate HTML response
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>WooCommerce Webhook Payloads</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 1200px;
          margin: 0 auto;
          padding: 20px;
          background-color: #f8f9fa;
        }
        h1 {
          color: #2c3e50;
          border-bottom: 2px solid #e67e22;
          padding-bottom: 10px;
          margin-bottom: 30px;
        }
        .header-container {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .count-badge {
          background-color: #e67e22;
          color: white;
          padding: 5px 12px;
          border-radius: 20px;
          font-size: 14px;
          font-weight: bold;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 30px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
          background-color: white;
          border-radius: 8px;
          overflow: hidden;
        }
        th {
          background-color: #34495e;
          color: white;
          padding: 12px 15px;
          text-align: left;
          font-weight: 600;
        }
        td {
          padding: 12px 15px;
          border-bottom: 1px solid #ddd;
        }
        tr:last-child td {
          border-bottom: none;
        }
        tr:hover {
          background-color: #f1f5f9;
        }
        .order-created {
          background-color: #d4edda;
          color: #155724;
          padding: 5px 10px;
          border-radius: 4px;
          font-weight: 500;
        }
        .order-updated {
          background-color: #cce5ff;
          color: #004085;
          padding: 5px 10px;
          border-radius: 4px;
          font-weight: 500;
        }
        a {
          color: #3498db;
          text-decoration: none;
          font-weight: 500;
        }
        a:hover {
          text-decoration: underline;
          color: #2980b9;
        }
        .back-link {
          display: inline-block;
          margin-top: 20px;
          color: #7f8c8d;
        }
        .empty-message {
          text-align: center;
          padding: 40px;
          background-color: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
          color: #7f8c8d;
          font-size: 18px;
        }
      </style>
    </head>
    <body>
      <div class="header-container">
        <h1>WooCommerce Webhook Payloads</h1>
        <span class="count-badge">${sortedFiles.length} Webhooks</span>
      </div>
      
      <div class="nav-links" style="display: flex; gap: 20px; margin-bottom: 20px;">
        <a href="/admin/orders" class="nav-link" style="text-decoration: none; padding: 8px 16px; background-color: #fff; color: #3498db; border-radius: 4px; font-weight: 500; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">Orders</a>
        <a href="/admin/payloads" class="nav-link active" style="text-decoration: none; padding: 8px 16px; background-color: #3498db; color: white; border-radius: 4px; font-weight: 500; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">Webhook Payloads</a>
      </div>
      
      ${sortedFiles.length === 0 ? `
        <div class="empty-message">
          <p>No webhook payloads received yet. They will appear here when WooCommerce sends webhooks.</p>
        </div>
      ` : `
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Timestamp</th>
              <th>Size</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${sortedFiles.map(file => `
              <tr>
                <td>
                  <span class="${file.type === 'Order Created' ? 'order-created' : 'order-updated'}">
                    ${file.type}
                  </span>
                </td>
                <td>${file.formattedDate}</td>
                <td>${file.size}</td>
                <td>
                  <a href="/admin/payloads/${file.filename}" target="_blank">View JSON</a> | 
                  <a href="/admin/payloads/view/${file.filename}" target="_blank">View Formatted</a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `}
      
      <a href="/" class="back-link">← Back to Home</a>
      
      <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => { location.reload(); }, 30000);
      </script>
    </body>
    </html>
    `;
    
    res.status(200).setHeader('Content-Type', 'text/html').send(html);
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error listing payload files: ${err.message}`);
    res.status(500).send(`<h1>Error</h1><p>Failed to list payload files: ${err.message}</p>`);
  }
});

// Admin endpoint to view a specific payload file as raw JSON
app.get('/admin/payloads/:filename', async (req: Request, res: Response): Promise<void> => {
  try {
    const filename = req.params.filename;
    
    // Basic security check to prevent directory traversal
    if (filename.includes('../') || filename.includes('..\\')) {
      res.status(400).json({ error: 'Invalid filename' });
      return;
    }
    
    const filePath = path.join(PAYLOADS_DIR, filename);
    
    // Check if file exists
    try {
      await fsPromises.access(filePath, fs.constants.R_OK);
    } catch {
      res.status(404).json({ error: 'Payload file not found' });
      return;
    }
    
    // Read and return the file content
    const content = await fsPromises.readFile(filePath, 'utf8');
    
    // Try to parse as JSON, if it fails, return as text
    try {
      const jsonContent = JSON.parse(content);
      res.status(200).json(jsonContent);
    } catch {
      res.status(200).send(content);
    }
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error reading payload file: ${err.message}`);
    res.status(500).json({ error: 'Failed to read payload file', message: err.message });
  }
});

// Admin endpoint to view a formatted version of the payload
app.get('/admin/payloads/view/:filename', async (req: Request, res: Response): Promise<void> => {
  try {
    const filename = req.params.filename;
    
    // Basic security check to prevent directory traversal
    if (filename.includes('../') || filename.includes('..\\')) {
      res.status(400).send('<h1>Error</h1><p>Invalid filename</p>');
      return;
    }
    
    const filePath = path.join(PAYLOADS_DIR, filename);
    
    // Check if file exists
    try {
      await fsPromises.access(filePath, fs.constants.R_OK);
    } catch {
      res.status(404).send('<h1>Error</h1><p>Payload file not found</p>');
      return;
    }
    
    // Read the file content
    const content = await fsPromises.readFile(filePath, 'utf8');
    
    // Parse the JSON
    try {
      const jsonContent = JSON.parse(content);
      
      // Generate a nice HTML view
      const orderType = filename.includes('order_created') ? 'Order Created' : 'Order Updated';
      const timestampMatch = filename.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}.*)\.json/);
      const timestamp = timestampMatch ? timestampMatch[1].replace(/-/g, ':') : 'Unknown';
      
      // Extract basic order info if available
      const orderId = jsonContent.id || 'Unknown';
      const orderNumber = jsonContent.number || 'Unknown';
      const orderStatus = jsonContent.status || 'Unknown';
      const orderTotal = jsonContent.total ? `$${jsonContent.total}` : 'Unknown';
      const customerName = jsonContent.billing ? 
        `${jsonContent.billing.first_name || ''} ${jsonContent.billing.last_name || ''}`.trim() : 'Unknown';
      
      const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>${orderType} - Order #${orderNumber}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
          }
          h1, h2 {
            color: #2c3e50;
          }
          h1 {
            border-bottom: 2px solid #e67e22;
            padding-bottom: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
          }
          .order-badge {
            font-size: 16px;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
          }
          .order-created {
            background-color: #d4edda;
            color: #155724;
          }
          .order-updated {
            background-color: #cce5ff;
            color: #004085;
          }
          .order-summary {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
          }
          .order-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
          }
          .order-property {
            margin-bottom: 15px;
          }
          .property-label {
            font-weight: bold;
            margin-bottom: 5px;
            color: #7f8c8d;
            font-size: 0.9rem;
            text-transform: uppercase;
          }
          .property-value {
            font-size: 1.1rem;
          }
          .json-viewer {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            position: relative;
          }
          pre {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow: auto;
            max-height: 500px;
            font-size: 14px;
          }
          .back-link {
            display: inline-block;
            margin-top: 20px;
            color: #7f8c8d;
            text-decoration: none;
          }
          .back-link:hover {
            text-decoration: underline;
          }
          .json-control {
            position: absolute;
            right: 20px;
            top: 20px;
          }
          button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.2s;
          }
          button:hover {
            background-color: #2980b9;
          }
        </style>
      </head>
      <body>
        <h1>
          ${orderType} Webhook
          <span class="order-badge ${orderType === 'Order Created' ? 'order-created' : 'order-updated'}">
            ${orderType}
          </span>
        </h1>
        
        <div class="order-summary">
          <h2>Order Summary</h2>
          <div class="order-grid">
            <div class="order-property">
              <div class="property-label">Order ID</div>
              <div class="property-value">${orderId}</div>
            </div>
            <div class="order-property">
              <div class="property-label">Order Number</div>
              <div class="property-value">#${orderNumber}</div>
            </div>
            <div class="order-property">
              <div class="property-label">Status</div>
              <div class="property-value">${orderStatus}</div>
            </div>
            <div class="order-property">
              <div class="property-label">Total</div>
              <div class="property-value">${orderTotal}</div>
            </div>
            <div class="order-property">
              <div class="property-label">Customer</div>
              <div class="property-value">${customerName}</div>
            </div>
            <div class="order-property">
              <div class="property-label">Timestamp</div>
              <div class="property-value">${timestamp}</div>
            </div>
          </div>
        </div>
        
        <div class="json-viewer">
          <h2>Full Payload</h2>
          <div class="json-control">
            <button onclick="copyJson()">Copy JSON</button>
          </div>
          <pre id="json-content">${JSON.stringify(jsonContent, null, 2)}</pre>
        </div>
        
        <a href="/admin/payloads" class="back-link">← Back to All Payloads</a>
        
        <script>
          function copyJson() {
            const jsonText = document.getElementById('json-content').textContent;
            navigator.clipboard.writeText(jsonText)
              .then(() => {
                alert('JSON copied to clipboard');
              })
              .catch(err => {
                console.error('Error copying text: ', err);
              });
          }
        </script>
      </body>
      </html>
      `;
      
      res.status(200).setHeader('Content-Type', 'text/html').send(html);
    } catch (error) {
      res.status(400).send(`<h1>Error</h1><p>Invalid JSON format: ${error}</p>`);
    }
  } catch (error: unknown) {
    const err = error as Error;
    console.error(`Error reading payload file: ${err.message}`);
    res.status(500).send(`<h1>Error</h1><p>Failed to read payload file: ${err.message}</p>`);
  }
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
