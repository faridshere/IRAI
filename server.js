require('dotenv').config();
const express = require('express');
const multer = require('multer');
const OpenAI = require('openai');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for image uploads (memory storage, no disk writes)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, GIF, WEBP) are allowed'));
    }
  },
});

// Initialize OpenAI client only when a key is available
function getOpenAIClient() {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey === 'your_openai_api_key_here') {
    return null;
  }
  return new OpenAI({ apiKey });
}

// System prompts per mode
const SYSTEM_PROMPTS = {
  cortex: `You are an expert security analyst specializing in Palo Alto Networks Cortex XDR.
You help with:
- Writing and debugging XQL (Cortex XQL) queries
- Creating and optimizing Cortex XDR detection rules (BIOC and BIOC-R)
- Incident investigation workflows and playbooks
- Alert triage and threat hunting using Cortex XDR
- Converting Sigma rules to Cortex XDR / XQL format
- Best practices for Cortex XDR deployment and configuration
When providing XQL queries or rules, always format them in code blocks and explain what they do.`,

  qradar: `You are an expert security analyst specializing in IBM QRadar SIEM.
You help with:
- Writing AQL (Ariel Query Language) queries for QRadar
- Creating and tuning QRadar correlation rules and building blocks
- Log source configuration and parsing (DSM)
- Offense investigation and threat hunting in QRadar
- Converting Sigma rules to QRadar AQL or correlation rule format
- QRadar reference sets, reference maps, and custom properties
- Best practices for QRadar deployment and tuning
When providing AQL queries or rules, always format them in code blocks and explain what they do.`,

  sigma: `You are an expert in Sigma rules and security detection engineering.
You help with:
- Writing Sigma rules from scratch following the official specification
- Converting Sigma rules to platform-specific formats:
  * Cortex XDR / XQL queries
  * QRadar AQL queries and correlation rules
  * Splunk SPL, Elastic EQL, and other SIEM formats
- Validating and improving existing Sigma rules
- Explaining Sigma rule logic and detection coverage
- Mapping detections to MITRE ATT&CK techniques
Always output well-formatted YAML for Sigma rules and properly indented code blocks for converted queries.`,

  general: `You are IRAI, an intelligent security assistant specializing in Security Operations and SIEM platforms.
You have deep expertise in:
- Cortex XDR by Palo Alto Networks (XQL queries, BIOC rules, incident response)
- IBM QRadar SIEM (AQL queries, correlation rules, DSM configuration)
- Sigma rules and detection engineering
- Threat hunting and incident investigation
- MITRE ATT&CK framework
- General cybersecurity, SOC operations, and threat intelligence
Be concise, accurate, and always provide practical, actionable answers.
When writing queries or rules, use proper code blocks and explain the logic.`,
};

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'docs')));

// Rate limiters
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});
const staticLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});

// Health check
app.get('/api/health', apiLimiter, (req, res) => {
  const hasKey = !!(
    process.env.OPENAI_API_KEY &&
    process.env.OPENAI_API_KEY !== 'your_openai_api_key_here'
  );
  res.json({ status: 'ok', configured: hasKey });
});

// Chat endpoint
app.post('/api/chat', apiLimiter, upload.single('image'), async (req, res) => {
  try {
    const openai = getOpenAIClient();
    if (!openai) {
      return res.status(503).json({
        error:
          'OpenAI API key not configured. Please set OPENAI_API_KEY in your .env file.',
      });
    }

    const { message, mode = 'general', history } = req.body;

    if (!message && !req.file) {
      return res.status(400).json({ error: 'Message or image is required' });
    }

    const systemPrompt = SYSTEM_PROMPTS[mode] || SYSTEM_PROMPTS.general;

    // Build conversation messages
    const messages = [{ role: 'system', content: systemPrompt }];

    // Add conversation history (last 20 messages to stay within context limits)
    if (history) {
      const parsedHistory = JSON.parse(history);
      const recent = parsedHistory.slice(-20);
      for (const msg of recent) {
        messages.push({ role: msg.role, content: msg.content });
      }
    }

    // Build the current user message
    let userContent;
    if (req.file) {
      const base64Image = req.file.buffer.toString('base64');
      const mimeType = req.file.mimetype;
      userContent = [
        {
          type: 'image_url',
          image_url: { url: `data:${mimeType};base64,${base64Image}` },
        },
      ];
      if (message) {
        userContent.unshift({ type: 'text', text: message });
      } else {
        userContent.unshift({
          type: 'text',
          text: 'Please analyze this image.',
        });
      }
    } else {
      userContent = message;
    }

    messages.push({ role: 'user', content: userContent });

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages,
      max_tokens: 4096,
      temperature: 0.2,
    });

    const reply = completion.choices[0].message.content;
    res.json({
      reply,
      usage: completion.usage,
    });
  } catch (err) {
    console.error('Chat error:', err);
    if (err.code === 'invalid_api_key') {
      return res
        .status(401)
        .json({ error: 'Invalid OpenAI API key. Please check your configuration.' });
    }
    if (err.status === 429) {
      return res
        .status(429)
        .json({ error: 'Rate limit exceeded. Please wait a moment and try again.' });
    }
    res.status(500).json({ error: err.message || 'An unexpected error occurred' });
  }
});

// Serve frontend for all other routes
app.get('*', staticLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'docs', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 IRAI Security Chat running at http://localhost:${PORT}`);
  const hasKey = !!(
    process.env.OPENAI_API_KEY &&
    process.env.OPENAI_API_KEY !== 'your_openai_api_key_here'
  );
  if (!hasKey) {
    console.log('⚠️  No OpenAI API key found. Set OPENAI_API_KEY in .env to enable chat.');
  }
});
