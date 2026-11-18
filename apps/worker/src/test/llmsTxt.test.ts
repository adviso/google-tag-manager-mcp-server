import { expect, it } from "vitest";
import { apisHandler } from "../utils/apisHandler";

it("serves /llms.txt as plain text", async () => {
  const response = await apisHandler.request("/llms.txt");

  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toMatch(/^text\/plain/);

  const body = await response.text();
  // llms.txt format: an H1 title followed by a blockquote summary.
  expect(body).toMatch(/^# .+\n\n> .+/);
  expect(body).toContain("https://gtm-mcp.stape.io/mcp");
});

it("serves the branded OAuth success page", async () => {
  const response = await apisHandler.request("/oauth/success");

  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toMatch(/^text\/html/);
  expect(response.headers.get("cache-control")).toBe("no-store");

  const body = await response.text();
  expect(body).toContain("Connexion reussie");
  expect(body).toContain("Adviso");
  expect(body).toContain("Fermer cette fenêtre");
});
