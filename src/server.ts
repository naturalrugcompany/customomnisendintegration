import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { promisify } from 'util';
import { promises as fsPromises } from 'fs';

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
      '/admin/payloads',
      '/admin/payloads/:filename'
    ]
  });
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
