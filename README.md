# WooCommerce Webhook Receiver for Omnisend Integration

A webhook receiver application designed to capture and store WooCommerce webhook payloads for `order.created` and `order.updated` events. This is Phase 1 of a larger project to develop a custom Omnisend store integration.

## Project Overview

This application:
- Receives webhooks from WooCommerce
- Validates webhook signatures using HMAC SHA256
- Stores JSON payloads with timestamps in an organized directory
- Provides a beautiful web interface to view and analyze webhook payloads
- Is optimized for deployment on Railway

## Application Endpoints

### Webhook Endpoints

- **Order Created**: `POST /webhooks/woocommerce/order-created`
- **Order Updated**: `POST /webhooks/woocommerce/order-updated`

### Admin Interface

- **Payload List**: `GET /admin/payloads` - Web interface showing all captured webhooks
- **View JSON Payload**: `GET /admin/payloads/:filename` - Raw JSON data for a specific webhook
- **View Formatted Payload**: `GET /admin/payloads/view/:filename` - User-friendly interface for viewing webhook details

### Other Endpoints

- **Health Check**: `GET /` - Returns service status information

## Deployment to Railway

### Prerequisites

- GitHub account
- Railway account (https://railway.app)
- WooCommerce store with admin access

### Deployment Steps

1. **Push the code to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin <your-github-repo-url>
   git push -u origin main
   ```

2. **Deploy to Railway**
   - Log in to Railway
   - Click "New Project" > "Deploy from GitHub repo"
   - Select your repository
   - Railway will automatically detect the Node.js project and deploy it

3. **Configure Environment Variables**
   - In Railway project settings, add the following environment variables:
     - `WC_ORDER_CREATED_SECRET`: Your WooCommerce order.created webhook secret
     - `WC_ORDER_UPDATED_SECRET`: Your WooCommerce order.updated webhook secret
     - `NODE_ENV`: Set to `production`

4. **Get Your Deployment URL**
   - Once deployed, Railway will provide a URL for your application
   - This URL will be used to configure your WooCommerce webhooks

## Configuring WooCommerce Webhooks

1. In your WordPress admin dashboard, navigate to WooCommerce > Settings > Advanced > Webhooks
2. Add two webhooks:
   - **Order Created**:
     - Name: Omnisend Order Created
     - Status: Active
     - Topic: Order created (order.created)
     - Delivery URL: Your Railway URL + `/webhooks/woocommerce/order-created`
     - Secret: Create a strong secret and save it (you'll add this to Railway env vars)
     - API version: WP REST API Integration v3
   - **Order Updated**:
     - Name: Omnisend Order Updated
     - Status: Active
     - Topic: Order updated (order.updated)
     - Delivery URL: Your Railway URL + `/webhooks/woocommerce/order-updated`
     - Secret: Create a strong secret and save it (you'll add this to Railway env vars)
     - API version: WP REST API Integration v3

## Testing

1. After configuring both Railway and WooCommerce:
   - Create a new test order in your WooCommerce store to trigger `order.created`
   - Modify an existing order to trigger `order.updated`
2. Check the Railway logs to confirm successful receipt of webhooks
3. Webhook payloads will be saved in the `example-payloads` directory with timestamps

## Local Development

### Prerequisites

- [Node.js](https://nodejs.org/) (v16 or newer)
- [npm](https://www.npmjs.com/)

### Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Create a `.env` file with the required variables:
   ```
   WC_ORDER_CREATED_SECRET=your_secret_here
   WC_ORDER_UPDATED_SECRET=your_secret_here
   ```
4. Run in development mode: `npm run dev`

## Key Features

### Beautiful Admin Interface

The application includes a user-friendly admin interface that allows you to:

- View a list of all received webhooks with metadata
- See nicely formatted order information from webhooks
- Access and copy the raw JSON payload data
- Automatically refresh to show new webhooks as they arrive

### Robust Webhook Signature Validation

- Implements proper HMAC SHA256 signature validation according to WooCommerce specs
- Captures raw request bodies to ensure exact signature matching
- Provides detailed logging for troubleshooting signature issues

### Secure Storage

- Stores webhooks with timestamps to prevent overwriting
- Organizes payloads in the `example-payloads` directory
- Makes payloads accessible through the web interface

## Next Steps (Phase 2)

- Analyze captured webhook payloads to understand data structure
- Design a standardized internal format for order data
- Develop adapters to transform WooCommerce data
- Implement Omnisend API integration
