// workers-oauth-utils.ts

import type {
  ClientInfo,
  AuthRequest,
} from "@cloudflare/workers-oauth-provider"; // Adjust path if necessary

const COOKIE_NAME = "mcp-approved-clients";
const ONE_YEAR_IN_SECONDS = 31536000;

/**
 * Decodes a URL-safe base64 string back to its original data.
 * @param encoded - The URL-safe base64 encoded string.
 * @returns The original data.
 */
function decodeState<T = unknown>(encoded: string): T {
  try {
    const jsonString = atob(encoded);
    return JSON.parse(jsonString);
  } catch (e) {
    console.error("Error decoding state:", e);
    throw new Error("Could not decode state");
  }
}

/**
 * Imports a secret key string for HMAC-SHA256 signing.
 * @param secret - The raw secret key string.
 * @returns A promise resolving to the CryptoKey object.
 */
async function importKey(secret: string): Promise<CryptoKey> {
  if (!secret) {
    throw new Error(
      "COOKIE_SECRET is not defined. A secret key is required for signing cookies.",
    );
  }
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, // not extractable
    ["sign", "verify"], // key usages
  );
}

/**
 * Signs data using HMAC-SHA256.
 * @param key - The CryptoKey for signing.
 * @param data - The string data to sign.
 * @returns A promise resolving to the signature as a hex string.
 */
async function signData(key: CryptoKey, data: string): Promise<string> {
  const enc = new TextEncoder();
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(data),
  );
  // Convert ArrayBuffer to hex string
  return Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verifies an HMAC-SHA256 signature.
 * @param key - The CryptoKey for verification.
 * @param signatureHex - The signature to verify (hex string).
 * @param data - The original data that was signed.
 * @returns A promise resolving to true if the signature is valid, false otherwise.
 */
async function verifySignature(
  key: CryptoKey,
  signatureHex: string,
  data: string,
): Promise<boolean> {
  const enc = new TextEncoder();
  try {
    // Convert hex signature back to ArrayBuffer
    const signatureBytes = new Uint8Array(
      signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
    );
    return await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes.buffer,
      enc.encode(data),
    );
  } catch (e) {
    // Handle errors during hex parsing or verification
    console.error("Error verifying signature:", e);
    return false;
  }
}

/**
 * Parses the signed cookie and verifies its integrity.
 * @param cookieHeader - The value of the Cookie header from the request.
 * @param secret - The secret key used for signing.
 * @returns A promise resolving to the list of approved client IDs if the cookie is valid, otherwise null.
 */
async function getApprovedClientsFromCookie(
  cookieHeader: string | null,
  secret: string,
): Promise<string[] | null> {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const targetCookie = cookies.find((c) => c.startsWith(`${COOKIE_NAME}=`));

  if (!targetCookie) return null;

  const cookieValue = targetCookie.substring(COOKIE_NAME.length + 1);
  const parts = cookieValue.split(".");

  if (parts.length !== 2) {
    console.warn("Invalid cookie format received.");
    return null; // Invalid format
  }

  const [signatureHex, base64Payload] = parts;
  const payload = atob(base64Payload); // Assuming payload is base64 encoded JSON string

  const key = await importKey(secret);
  const isValid = await verifySignature(key, signatureHex, payload);

  if (!isValid) {
    console.warn("Cookie signature verification failed.");
    return null; // Signature invalid
  }

  try {
    const approvedClients = JSON.parse(payload);
    if (!Array.isArray(approvedClients)) {
      console.warn("Cookie payload is not an array.");
      return null; // Payload isn't an array
    }
    // Ensure all elements are strings
    if (!approvedClients.every((item) => typeof item === "string")) {
      console.warn("Cookie payload contains non-string elements.");
      return null;
    }
    return approvedClients as string[];
  } catch (e) {
    console.error("Error parsing cookie payload:", e);
    return null; // JSON parsing failed
  }
}

// --- Exported Functions ---

/**
 * Checks if a given client ID has already been approved by the user,
 * based on a signed cookie.
 *
 * @param request - The incoming Request object to read cookies from.
 * @param clientId - The OAuth client ID to check approval for.
 * @param cookieSecret - The secret key used to sign/verify the approval cookie.
 * @returns A promise resolving to true if the client ID is in the list of approved clients in a valid cookie, false otherwise.
 */
export async function clientIdAlreadyApproved(
  request: Request,
  clientId: string,
  cookieSecret: string,
): Promise<boolean> {
  if (!clientId) return false;
  const cookieHeader = request.headers.get("Cookie");
  const approvedClients = await getApprovedClientsFromCookie(
    cookieHeader,
    cookieSecret,
  );

  return approvedClients?.includes(clientId) ?? false;
}

/**
 * Configuration for the approval dialog
 */
export interface ApprovalDialogOptions {
  /**
   * Client information to display in the approval dialog
   */
  client: ClientInfo | null;
  /**
   * Server information to display in the approval dialog
   */
  server: {
    name: string;
    logo?: string;
    description?: string;
    /** Trusted HTML shown below the approval card, not escaped. */
    noticeHtml?: string;
  };
  /**
   * Arbitrary state data to pass through the approval flow
   * Will be encoded in the form and returned when approval is complete
   */
  state: Record<string, unknown>;
  /**
   * Name of the cookie to use for storing approvals
   * @default "mcp_approved_clients"
   */
  cookieName?: string;
  /**
   * Secret used to sign cookies for verification
   * Can be a string or Uint8Array
   * @default Built-in Uint8Array key
   */
  cookieSecret?: string | Uint8Array;
  /**
   * Cookie domain
   * @default current domain
   */
  cookieDomain?: string;
  /**
   * Cookie path
   * @default "/"
   */
  cookiePath?: string;
  /**
   * Cookie max age in seconds
   * @default 30 days
   */
  cookieMaxAge?: number;
}

/**
 * Renders an approval dialog for OAuth authorization
 * The dialog displays information about the client and server
 * and includes a form to submit approval
 *
 * @param request - The HTTP request
 * @param options - Configuration for the approval dialog
 * @returns A Response containing the HTML approval dialog
 */
export function renderApprovalDialog(
  request: Request,
  options: ApprovalDialogOptions,
): Response {
  const { client, server, state } = options;

  // Encode state for form submission
  const encodedState = btoa(JSON.stringify(state));

  // Sanitize any untrusted content
  const serverName = sanitizeHtml(server.name);
  const clientName = client?.clientName
    ? sanitizeHtml(client.clientName)
    : "Unknown MCP Client";
  const serverDescription = server.description
    ? sanitizeHtml(server.description)
    : "";

  // Safe URLs
  const logoUrl = server.logo ? sanitizeHtml(server.logo) : "";
  const clientUri = client?.clientUri ? sanitizeHtml(client.clientUri) : "";
  const policyUri = client?.policyUri ? sanitizeHtml(client.policyUri) : "";
  const tosUri = client?.tosUri ? sanitizeHtml(client.tosUri) : "";

  // Client contacts
  const contacts =
    client?.contacts && client.contacts.length > 0
      ? sanitizeHtml(client.contacts.join(", "))
      : "";

  // Get redirect URIs
  const redirectUris =
    client?.redirectUris && client.redirectUris.length > 0
      ? client.redirectUris.map((uri) => sanitizeHtml(uri))
      : [];

  // Generate HTML for the approval dialog
  const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${clientName} | Authorization Request</title>
        <style>
          /* Modern, responsive styling with system fonts */
          :root {
            --primary-color: #8540ff;
            --primary-hover: #6f32dc;
            --ink-color: #17152b;
            --muted-color: #666378;
            --border-color: #e8e5ef;
            --text-color: #17152b;
            --background-color: #f7f6fa;
            --card-background: #fff;
            --card-shadow: 0 24px 70px rgba(23, 21, 43, 0.12);
          }
          
          html {
            display: flex;
            flex-direction: column;
            min-height: 100%;
          }
          
          body {
            display: flex;
            flex-direction: column;
            flex: 1 0 auto;
            font-family: "Aptos", "Segoe UI", Helvetica, Arial, sans-serif;
            line-height: 1.55;
            color: var(--text-color);
            background:
              radial-gradient(circle at 85% 12%, rgba(133, 64, 255, 0.10), transparent 24rem),
              linear-gradient(135deg, #fbfafc 0%, var(--background-color) 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
          }
          
          .container {
            display: flex;
            flex-direction: column;
            flex: 1 0 auto;
            width: min(640px, calc(100% - 32px));
            margin: auto;
            padding: 32px 0;
          }
          
          .precard {
            padding: 0 0 24px;
            text-align: center;
          }
          
          .card {
            background: var(--card-background);
            border: 1px solid rgba(23, 21, 43, 0.06);
            border-radius: 8px;
            box-shadow: var(--card-shadow);
            padding: 40px;
          }
          
          .header {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 56px;
          }
          
          .logo {
            width: 148px;
            height: 40px;
            object-fit: contain;
          }
          
          .title {
            display: none;
          }
          
          .alert {
            margin: 0 0 24px;
            font-size: clamp(24px, 5vw, 32px);
            font-weight: 700;
            line-height: 1.15;
            letter-spacing: 0;
            text-align: left;
          }
          
          .description {
            color: #555;
          }
          
          .client-info {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: #faf9fc;
            padding: 16px 20px 8px;
            margin-bottom: 24px;
          }
          
          .client-name {
            font-weight: 600;
            font-size: 1.2rem;
            margin: 0 0 0.5rem 0;
          }
          
          .client-detail {
            display: flex;
            margin-bottom: 0.5rem;
            align-items: baseline;
          }
          
          .detail-label {
            font-weight: 500;
            min-width: 120px;
          }
          
          .detail-value {
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            word-break: break-all;
          }
          
          .detail-value a {
            color: inherit;
            text-decoration: underline;
          }
          
          .detail-value.small {
            font-size: 0.8em;
          }
          
          .external-link-icon {
            font-size: 0.75em;
            margin-left: 0.25rem;
            vertical-align: super;
          }
          
          .actions {
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
            margin-top: 2rem;
          }
          
          .button {
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            font-size: 1rem;
          }
          
          .button-primary {
            background: var(--primary-color);
            color: white;
            min-width: 120px;
          }

          .button-primary:hover {
            background: var(--primary-hover);
          }
          
          .button-secondary {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-color);
          }
          
          footer {
            display: flex;
            justify-content: center;
            column-gap: 24px;
            padding: 0 16px 24px;
            font-size: 14px;
          }

          footer a {
            color: var(--muted-color);
          }
          
          /* Responsive adjustments */
          @media (max-width: 640px) {
            .container {
              margin: 1rem auto;
              padding: 0.5rem;
            }
            
            .card {
              padding: 1.5rem;
            }
            
            .client-detail {
              flex-direction: column;
            }
            
            .detail-label {
              min-width: unset;
              margin-bottom: 0.25rem;
            }
            
            .actions {
              flex-direction: column;
            }
            
            .button {
              width: 100%;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="precard">
            <div class="header">
              ${logoUrl ? `<img src="${logoUrl}" alt="${serverName} Logo" class="logo">` : ""}
              <h1 class="title">
                <a href="/">
                  <strong>${serverName}</strong>
                </a>
              </h1>
            </div>
            
            ${serverDescription ? `<p class="description">${serverDescription}</p>` : ""}
          </div>
          ${server.noticeHtml ?? ""}

          <div class="card">
            
            <h2 class="alert"><strong>${clientName || "A new MCP Client"}</strong> is requesting access</h1>
            
            <div class="client-info">
              <div class="client-detail">
                <div class="detail-label">Name:</div>
                <div class="detail-value">
                  ${clientName}
                </div>
              </div>
              
              ${
                clientUri
                  ? `
                <div class="client-detail">
                  <div class="detail-label">Website:</div>
                  <div class="detail-value small">
                    <a href="${clientUri}" target="_blank" rel="noopener noreferrer">
                      ${clientUri}
                    </a>
                  </div>
                </div>
              `
                  : ""
              }
              
              ${
                policyUri
                  ? `
                <div class="client-detail">
                  <div class="detail-label">Privacy Policy:</div>
                  <div class="detail-value">
                    <a href="${policyUri}" target="_blank" rel="noopener noreferrer">
                      ${policyUri}
                    </a>
                  </div>
                </div>
              `
                  : ""
              }
              
              ${
                tosUri
                  ? `
                <div class="client-detail">
                  <div class="detail-label">Terms of Service:</div>
                  <div class="detail-value">
                    <a href="${tosUri}" target="_blank" rel="noopener noreferrer">
                      ${tosUri}
                    </a>
                  </div>
                </div>
              `
                  : ""
              }
              
              ${
                redirectUris.length > 0
                  ? `
                <div class="client-detail">
                  <div class="detail-label">Redirect URIs:</div>
                  <div class="detail-value small">
                    ${redirectUris.map((uri) => `<div>${uri}</div>`).join("")}
                  </div>
                </div>
              `
                  : ""
              }
              
              ${
                contacts
                  ? `
                <div class="client-detail">
                  <div class="detail-label">Contact:</div>
                  <div class="detail-value">${contacts}</div>
                </div>
              `
                  : ""
              }
            </div>
            
            <p>This MCP Client is requesting to be authorized on ${serverName}. If you approve, you will be redirected to complete authentication.</p>
            
            <form method="post" action="${new URL(request.url).pathname}">
              <input type="hidden" name="state" value="${encodedState}">
              
              <div class="actions">
                <button type="button" class="button button-secondary" onclick="window.history.back()">Cancel</button>
                <button type="submit" class="button button-primary">Approve</button>
              </div>
            </form>
          </div>
        </div>
        <footer>
          <a href="/privacy">Privacy Policy</a>
          <a href="/terms">Terms of Service</a>
        </footer>
      </body>
    </html>
  `;

  return new Response(htmlContent, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

export function renderOAuthSuccessPage(): Response {
  const htmlContent = `
    <!DOCTYPE html>
    <html lang="fr">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex,nofollow">
        <title>Connexion reussie | Adviso</title>
        <style>
          :root {
            --primary: #8540ff;
            --primary-hover: #6f32dc;
            --ink: #17152b;
            --muted: #666378;
            --border: #e8e5ef;
            --surface: #f7f6fa;
          }

          * { box-sizing: border-box; }

          html, body { min-height: 100%; }

          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            font-family: "Aptos", "Segoe UI", Helvetica, Arial, sans-serif;
            color: var(--ink);
            background:
              radial-gradient(circle at 85% 12%, rgba(133, 64, 255, 0.10), transparent 24rem),
              linear-gradient(135deg, #fbfafc 0%, var(--surface) 100%);
          }

          main {
            width: min(560px, 100%);
            background: #fff;
            border: 1px solid rgba(23, 21, 43, 0.06);
            border-radius: 8px;
            box-shadow: 0 24px 70px rgba(23, 21, 43, 0.12);
            padding: 48px;
            text-align: center;
          }

          .logo {
            width: 148px;
            height: 40px;
            object-fit: contain;
          }

          .status {
            width: 56px;
            height: 56px;
            margin: 32px auto 20px;
            display: grid;
            place-items: center;
            border-radius: 50%;
            background: #eee7ff;
            color: var(--primary);
          }

          .status svg {
            width: 28px;
            height: 28px;
          }

          h1 {
            margin: 0;
            font-size: clamp(28px, 6vw, 36px);
            line-height: 1.1;
            letter-spacing: 0;
          }

          p {
            max-width: 420px;
            margin: 16px auto 28px;
            color: var(--muted);
            line-height: 1.55;
          }

          button {
            min-width: 180px;
            border: 0;
            border-radius: 6px;
            padding: 13px 20px;
            background: var(--primary);
            color: #fff;
            font: inherit;
            font-weight: 650;
            cursor: pointer;
          }

          button:hover { background: var(--primary-hover); }

          @media (max-width: 640px) {
            body { padding: 16px; }
            main { padding: 32px 20px; }
          }
        </style>
      </head>
      <body>
        <main>
          <img class="logo" src="https://www.adviso.ca/hubfs/logo_adviso/Advido-co.svg" alt="Adviso">
          <div class="status" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 6 9 17l-5-5"/>
            </svg>
          </div>
          <h1>Connexion reussie</h1>
          <p>Votre accès Google Tag Manager est maintenant autorisé. Vous pouvez fermer cette fenêtre et retourner à votre client MCP.</p>
          <button type="button" onclick="window.close();">Fermer cette fenêtre</button>
        </main>
        <script>
          window.close();
        </script>
      </body>
    </html>
  `;

  return new Response(htmlContent, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

/**
 * Result of parsing the approval form submission.
 */
export interface ParsedApprovalResult {
  /** The original state object passed through the form. */
  state: Record<string, unknown> & { oauthReqInfo?: AuthRequest };
  /** Headers to set on the redirect response, including the Set-Cookie header. */
  headers: Record<string, string>;
}

/**
 * Parses the form submission from the approval dialog, extracts the state,
 * and generates Set-Cookie headers to mark the client as approved.
 *
 * @param request - The incoming POST Request object containing the form data.
 * @param cookieSecret - The secret key used to sign the approval cookie.
 * @returns A promise resolving to an object containing the parsed state and necessary headers.
 * @throws If the request method is not POST, form data is invalid, or state is missing.
 */
export async function parseRedirectApproval(
  request: Request,
  cookieSecret: string,
): Promise<ParsedApprovalResult> {
  if (request.method !== "POST") {
    throw new Error("Invalid request method. Expected POST.");
  }

  let state: ParsedApprovalResult["state"];
  let clientId: string | undefined;

  try {
    const formData = await request.formData();
    const encodedState = formData.get("state");

    if (typeof encodedState !== "string" || !encodedState) {
      throw new Error("Missing or invalid 'state' in form data.");
    }

    state = decodeState<ParsedApprovalResult["state"]>(encodedState); // Decode the state
    clientId = state?.oauthReqInfo?.clientId; // Extract clientId from within the state

    if (!clientId) {
      throw new Error("Could not extract clientId from state object.");
    }
  } catch (e) {
    console.error("Error processing form submission:", e);
    // Rethrow or handle as appropriate, maybe return a specific error response
    throw new Error(
      `Failed to parse approval form: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // Get existing approved clients
  const cookieHeader = request.headers.get("Cookie");
  const existingApprovedClients =
    (await getApprovedClientsFromCookie(cookieHeader, cookieSecret)) || [];

  // Add the newly approved client ID (avoid duplicates)
  const updatedApprovedClients = Array.from(
    new Set([...existingApprovedClients, clientId]),
  );

  // Sign the updated list
  const payload = JSON.stringify(updatedApprovedClients);
  const key = await importKey(cookieSecret);
  const signature = await signData(key, payload);
  const newCookieValue = `${signature}.${btoa(payload)}`; // signature.base64(payload)

  // Generate Set-Cookie header
  const headers: Record<string, string> = {
    "Set-Cookie": `${COOKIE_NAME}=${newCookieValue}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${ONE_YEAR_IN_SECONDS}`,
  };

  return { state, headers };
}

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param unsafe - The unsafe string that might contain HTML
 * @returns A safe string with HTML special characters escaped
 */
function sanitizeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
