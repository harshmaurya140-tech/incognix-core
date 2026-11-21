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
import { assessRisk } from "../src/utils/risk.js";
import { tokenize, detokenize } from "../src/core/tokenizer.js";



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


test("Returns zero risk when no findings are present", () => {
  const result = assessRisk([]);

  assert.equal(result.score, 0);
  assert.equal(result.level, "none");
  assert.equal(result.totalFindings, 0);
  assert.deepEqual(result.breakdown, {});
});

test("Scores a single critical finding accurately", () => {
  const result = assessRisk([
    { type: "API_KEY", risk: "critical", value: "sk-test", start: 0, end: 7 },
  ]);

  assert.equal(result.score, 85);
  assert.equal(result.level, "critical");
  assert.equal(result.totalFindings, 1);
  assert.deepEqual(result.breakdown, { API_KEY: 1 });
});

test("Escalates overall level to the highest severity finding", () => {
  const result = assessRisk([
    { type: "IP_ADDRESS", risk: "medium", value: "192.168.1.1", start: 0, end: 11 },
    { type: "CREDIT_CARD", risk: "high", value: "4111111111111111", start: 15, end: 31 },
  ]);

  assert.equal(result.level, "high");
  assert.equal(result.score, 60);
  assert.equal(result.totalFindings, 2);
  assert.deepEqual(result.breakdown, { IP_ADDRESS: 1, CREDIT_CARD: 1 });
});

test("Caps aggregate risk score at 100", () => {
  const result = assessRisk([
    { type: "API_KEY", risk: "critical", value: "k1", start: 0, end: 2 },
    { type: "API_KEY", risk: "critical", value: "k2", start: 3, end: 5 },
    { type: "CREDIT_CARD", risk: "high", value: "c1", start: 6, end: 8 },
  ]);

  assert.equal(result.score, 100);
  assert.equal(result.level, "critical");
});

test("Defaults unknown or missing risk levels to low", () => {
  const result = assessRisk([{ type: "CUSTOM", value: "abc", start: 0, end: 3 }]);

  assert.equal(result.score, 10);
  assert.equal(result.level, "low");
});

test("Throws a TypeError when findings is not an array", () => {
  assert.throws(() => assessRisk("not-an-array"), TypeError);
});


test("Tokenizes multiple PII findings in text order", () => {
  const input = "Contact harsh@example.com or 192.168.1.10";
  const findings = [
    { type: "EMAIL", value: "harsh@example.com", start: 8, end: 25, risk: "medium" },
    { type: "IP_ADDRESS", value: "192.168.1.10", start: 29, end: 41, risk: "medium" },
  ];

  const result = tokenize(input, findings);

  assert.equal(result.redactedText, "Contact [EMAIL_1] or [IP_ADDRESS_1]");
  assert.deepEqual(result.tokens, {
    "[EMAIL_1]": "harsh@example.com",
    "[IP_ADDRESS_1]": "192.168.1.10",
  });
});

test("Reuses the same token for repeated identical values", () => {
  const input = "Primary: a@b.com, Backup: a@b.com";
  const findings = [
    { type: "EMAIL", value: "a@b.com", start: 9, end: 16, risk: "medium" },
    { type: "EMAIL", value: "a@b.com", start: 26, end: 33, risk: "medium" },
  ];

  const result = tokenize(input, findings);

  assert.equal(result.redactedText, "Primary: [EMAIL_1], Backup: [EMAIL_1]");
  assert.deepEqual(result.tokens, { "[EMAIL_1]": "a@b.com" });
});

test("Resolves overlapping findings by prioritizing higher risk", () => {
  const input = "Secret: sk-proj-1234567890abcdefghijklmnop";
  const findings = [
    { type: "GENERIC", value: "sk-proj-1234567890abcdefghijklmnop", start: 8, end: 42, risk: "low" },
    { type: "API_KEY", value: "sk-proj-1234567890abcdefghijklmnop", start: 8, end: 42, risk: "critical" },
  ];

  const result = tokenize(input, findings);

  assert.equal(result.redactedText, "Secret: [API_KEY_1]");
  assert.equal(result.detections.length, 1);
  assert.equal(result.detections[0].type, "API_KEY");
});

test("Restores original text accurately with detokenize()", () => {
  const original = "Email harsh@example.com from 192.168.1.10";
  const findings = [
    { type: "EMAIL", value: "harsh@example.com", start: 6, end: 23, risk: "medium" },
    { type: "IP_ADDRESS", value: "192.168.1.10", start: 29, end: 41, risk: "medium" },
  ];

  const { redactedText, tokens } = tokenize(original, findings);
  const restored = detokenize(redactedText, tokens);

  assert.equal(restored, original);
});

test("Returns unchanged text when findings array is empty", () => {
  const result = tokenize("Clean prompt with no secrets", []);

  assert.equal(result.redactedText, "Clean prompt with no secrets");
  assert.deepEqual(result.tokens, {});
  assert.deepEqual(result.detections, []);
});

test("Throws TypeError for invalid tokenizer inputs", () => {
  assert.throws(() => tokenize(123, []), TypeError);
  assert.throws(() => tokenize("hello", "not-an-array"), TypeError);
  assert.throws(() => detokenize(123, {}), TypeError);
  assert.throws(() => detokenize("hello", null), TypeError);
});