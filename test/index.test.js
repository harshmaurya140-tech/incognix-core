import test from "node:test";
import assert from "node:assert/strict";
import { detectPhones } from "../src/detectors/phone.js";
import {
  detectCreditCards,
  passesLuhn
} from "../src/detectors/creditCard.js";
import { detectIPs } from "../src/detectors/ip.js";
import { detectEmails } from "../src/detectors/email.js";
import { detectApiKeys } from "../src/detectors/apiKey.js";

test("Detects a valid email address", () => {
const result = detectEmails("Contact me at harsh@example.com");

assert.equal(result.length, 1);
assert.equal(result[0].value, "harsh@example.com");
assert.equal(result[0].type, "EMAIL");
});

test("Detects multiple email addresses", () => {
const text =
"harsh@example.com and admin@company.org";

const result = detectEmails(text);

assert.equal(result.length, 2);
});

test("Returns an empty array when no email exists", () => {
const result = detectEmails("Hello, how are you?");

assert.equal(result.length, 0);
});

test("Rejects malformed email patterns", () => {
const result = detectEmails(
"Invalid: first..last@example.com"
);

assert.equal(result.length, 0);
});

test("Throws an error for non-string input", () => {
assert.throws(() => detectEmails(123), TypeError);
});


test("Detects an international phone number", () => {
  const result = detectPhones(
    "Call me at +1 213-373-4253"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].type, "PHONE");
  assert.equal(result[0].normalized, "+12133734253");
  assert.equal(result[0].country, "US");
});

test("Detects a national number using configured country", () => {
  const result = detectPhones(
    "Call me at (213) 373-4253",
    { defaultCountry: "US" }
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].normalized, "+12133734253");
});

test("Does not assume a country for national numbers", () => {
  const result = detectPhones("Call me at (213) 373-4253");

  assert.equal(result.length, 0);
});

test("Rejects invalid phone numbers", () => {
  const result = detectPhones("Call me at 12345");

  assert.equal(result.length, 0);
});

test("Throws an error for non-string input", () => {
  assert.throws(() => detectPhones(123), TypeError);
});

test("Rejects unsupported country configuration", () => {
  assert.throws(
    () => detectPhones("123456789", { defaultCountry: "ZZ" }),
    RangeError
  );
});




test("Detects a valid credit card test number", () => {
  const result = detectCreditCards(
    "Card: 4111111111111111"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].type, "CREDIT_CARD");
  assert.equal(result[0].category, "payment_card");
});

test("Detects formatted card numbers", () => {
  const result = detectCreditCards(
    "Card: 4111 1111 1111 1111"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].value, "4111 1111 1111 1111");
});

test("Rejects numbers that fail Luhn validation", () => {
  const result = detectCreditCards(
    "Card: 1234567890123456"
  );

  assert.equal(result.length, 0);
});

test("Rejects repeated-digit sequences", () => {
  const result = detectCreditCards(
    "Card: 0000000000000000"
  );

  assert.equal(result.length, 0);
});

test("Validates Luhn independently", () => {
  assert.equal(passesLuhn("4111111111111111"), true);
  assert.equal(passesLuhn("1234567890123456"), false);
});

test("Rejects non-numeric Luhn input", () => {
  assert.equal(passesLuhn("4111abcd"), false);
});

test("Throws an error for non-string input", () => {
  assert.throws(
    () => detectCreditCards(123),
    TypeError
  );
});

test("Rejects invalid length configuration", () => {
  assert.throws(
    () => detectCreditCards("4111111111111111", {
      minLength: 20,
      maxLength: 19
    }),
    RangeError
  );
});


test("Detects a valid IPv4 address", () => {
  const result = detectIPs(
    "Server address is 192.168.1.10"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].value, "192.168.1.10");
  assert.equal(result[0].version, 4);
});

test("Detects a valid IPv6 address", () => {
  const result = detectIPs(
    "Server address is 2001:db8::1"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].value, "2001:db8::1");
  assert.equal(result[0].version, 6);
});

test("Detects multiple IP addresses", () => {
  const result = detectIPs(
    "IPv4: 192.168.1.1 and IPv6: 2001:db8::1"
  );

  assert.equal(result.length, 2);
});

test("Rejects invalid IPv4 addresses", () => {
  const result = detectIPs(
    "Invalid address: 999.999.999.999"
  );

  assert.equal(result.length, 0);
});

test("Returns an empty array when no IP exists", () => {
  const result = detectIPs("Hello, how are you?");

  assert.equal(result.length, 0);
});

test("Throws an error for non-string input", () => {
  assert.throws(() => detectIPs(123), TypeError);
});


test("Detects an OpenAI-style API key", () => {
  const result = detectApiKeys(
    "My key is sk-proj-1234567890abcdefghijklmnop"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].type, "API_KEY");
  assert.equal(result[0].category, "secret");
  assert.equal(result[0].provider, "openai");
  assert.equal(result[0].risk, "critical");
});

test("Detects an Anthropic-style API key without duplicate match", () => {
  const result = detectApiKeys(
    "ANTHROPIC_API_KEY=sk-ant-api03-1234567890abcdefghijklmnop"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].provider, "anthropic");
});

test("Detects a GitHub personal access token", () => {
  const result = detectApiKeys(
    "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].provider, "github");
});

test("Detects an AWS access key ID", () => {
  const result = detectApiKeys("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");

  assert.equal(result.length, 1);
  assert.equal(result[0].provider, "aws");
});

test("Detects multiple API keys in text order", () => {
  const result = detectApiKeys(
    "AWS: AKIAIOSFODNN7EXAMPLE and GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
  );

  assert.equal(result.length, 2);
  assert.equal(result[0].provider, "aws");
  assert.equal(result[1].provider, "github");
});

test("Returns an empty array when no API key exists", () => {
  const result = detectApiKeys("This is a normal sentence with sk-short.");

  assert.equal(result.length, 0);
});

test("Throws an error for non-string input", () => {
  assert.throws(() => detectApiKeys(123), TypeError);
});