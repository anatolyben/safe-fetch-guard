import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { ssrfMiddleware } from "../src/express.js";

describe("ssrfMiddleware", () => {
  const app = express();
  app.use(express.json());
  
  // Custom middleware with default options
  app.use("/default", ssrfMiddleware(), (req, res) => {
    res.status(200).json({ success: true });
  });
  
  // Custom middleware allowing localhost
  app.use("/allow-local", ssrfMiddleware({ allowLocalhost: true }), (req, res) => {
    res.status(200).json({ success: true });
  });
  
  // Custom field
  app.use("/custom-field", ssrfMiddleware({ bodyFields: ["webhookUrl"] }), (req, res) => {
    res.status(200).json({ success: true });
  });

  it("allows valid public URLs in body", async () => {
    const res = await request(app)
      .post("/default")
      .send({ url: "https://example.com/webhook" });
    expect(res.status).toBe(200);
  });

  it("blocks private IPs in body URL (e.g. 169.254.169.254)", async () => {
    const res = await request(app)
      .post("/default")
      .send({ url: "http://169.254.169.254/latest/meta-data" });
    
    // Syntactically it's blocked as an invalid_or_private_url
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/Invalid URL/);
  });
  
  it("blocks localhost by default", async () => {
    const res = await request(app)
      .post("/default")
      .send({ url: "http://localhost:8080" });
    
    expect(res.status).toBe(400);
  });
  
  it("allows localhost if allowLocalhost is true", async () => {
    const res = await request(app)
      .post("/allow-local")
      .send({ url: "http://localhost:8080" });
    
    expect(res.status).toBe(200);
  });
  
  it("checks custom fields", async () => {
    const res = await request(app)
      .post("/custom-field")
      .send({ webhookUrl: "http://169.254.169.254/metadata" });
    
    expect(res.status).toBe(400);
  });
  
  it("allows requests without URL fields", async () => {
    const res = await request(app)
      .post("/default")
      .send({ someOtherField: "http://localhost" });
    
    expect(res.status).toBe(200);
  });
});
