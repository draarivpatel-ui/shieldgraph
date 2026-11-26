// Indirect prompt-injection scoring over de-obfuscated untrusted text.
import { combineWeights } from './util.mjs';
import { deobfuscate } from './deobfuscate.mjs';

// Each signal is a pattern family with a weight. Weights combine like
// independent probabilities, so one strong signal or several weak ones both score.
export const INJECTION_SIGNALS = [
  {
    id: 'authorityOverride', weight: 0.5, label: 'Authority override',
    pattern: /\b(ignore|disregard|forget|override|bypass|supersede)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system|developer|original)\b[^.\n]{0,24}\b(instructions?|rules?|prompts?|guidelines?|directives?|polic(?:y|ies)|guardrails?)\b/i
  },
  {
    id: 'roleSpoof', weight: 0.4, label: 'Fake system or role marker',
    pattern: /(^|\n)\s*(#{1,3}\s*)?(system|developer|assistant)\s*(prompt|message|note)?\s*:|<\/?\s*(system|assistant|developer|im_start|im_end)\s*>|\[\/?INST\]|<<\/?SYS>>|\bBEGIN (SYSTEM|ADMIN) (PROMPT|INSTRUCTIONS?)\b/i
  },
  {
    id: 'delimiterBreakout', weight: 0.35, label: 'Delimiter breakout',
    pattern: /<\/(tool_output|tool_result|document|context|untrusted|data|email|search_results?)>|-{3,}\s*end of (document|context|email|data|page)\b|\]\]>\s*\S|"""\s*\n\s*(new|updated|real) (instructions?|task)/i
  },
  {
    id: 'agentAddressed', weight: 0.3, label: 'Text addresses the AI agent directly',
    pattern: /\b(ai|assistant|agent|llm|language model|copilot|chatbot|bot)s?\b[^.\n]{0,40}\b(must|should|need to|are (now )?(required|instructed|authorized)|have to|will now)\b/i
  },
  {
    id: 'secrecy', weight: 0.35, label: 'Asks to hide actions from the user',
    pattern: /\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|show|showing|notify|notifying|ask|asking)\b[^.\n]{0,20}\b(the )?(user|human|owner|anyone|them)\b/i
  },
  {
    id: 'toolDirective', weight: 0.3, label: 'Directs a specific tool or command',
    pattern: /\b(run|execute|call|invoke|use|trigger)\b[^.\n]{0,30}\b(shell|terminal|command|bash|curl|wget|http_post|http_get|send_email|transfer_funds|write_file|read_file|function call|the tool)\b/i
  },
  {
    id: 'exfilVerb', weight: 0.3, label: 'Requests sending data outward',
    pattern: /\b(send|post|upload|forward|exfiltrate|leak|transmit|append|include|encode)\b[^\n]{0,50}?(\.env\b|\b(api[ _-]?keys?|tokens?|secrets?|passwords?|credentials?|private keys?|ssh keys?|session|cookies?|conversation|chat history)\b)/i
  },
  {
    id: 'urgentAction', weight: 0.2, label: 'Urgency paired with an action',
    pattern: /\b(urgent|immediately|right now|asap|before end of day|time[- ]sensitive)\b[^\n]{0,80}\b(wire|transfer|pay|run|execute|send|reset|approve)\b/i
  },
  {
    id: 'hiddenCarrier', weight: 0.25, label: 'Instruction hidden from human readers',
    pattern: /<!--[\s\S]{0,400}?\b(assistant|agent|ai|instruction|ignore|run|send)\b[\s\S]{0,400}?-->|display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(white|#fff\b|#ffffff)|visibility\s*:\s*hidden/i
  },
  {
    id: 'markdownBeacon', weight: 0.3, label: 'Markdown image beacon template',
    pattern: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*\?[^)\s]*(=|\{|<|\$)/i
  }
];

export function scoreInjection(text, options = {}) {
  const deob = options.deob || deobfuscate(text);
  const haystack = deob.analysisText;
  const hits = [];
  for (const signal of INJECTION_SIGNALS) {
    const m = haystack.match(signal.pattern);
    if (m) hits.push({ id: signal.id, label: signal.label, weight: signal.weight, excerpt: m[0].slice(0, 140) });
  }
  // Obfuscation is evidence of intent only when the hidden text itself carries a signal.
  const hiddenHits = [];
  for (const payload of deob.payloads) {
    for (const signal of INJECTION_SIGNALS) {
      if (signal.pattern.test(payload.decoded)) {
        hiddenHits.push({ id: 'obfuscatedInstruction', label: `Instruction hidden in ${payload.kind}`, weight: 0.3, excerpt: payload.decoded.slice(0, 140) });
        break;
      }
    }
  }
  if (hiddenHits.length) hits.push(hiddenHits[0]);
  const invisibleLayer = deob.layers.find((l) => l.id === 'invisible');
  const confusableLayer = deob.layers.find((l) => l.id === 'confusables');
  if (hits.length && invisibleLayer && invisibleLayer.count >= 3) {
    hits.push({ id: 'invisibleText', label: 'Zero-width or tag characters around an instruction', weight: 0.15, excerpt: `${invisibleLayer.count} invisible characters` });
  }
  if (hits.length && confusableLayer && confusableLayer.count >= 2) {
    hits.push({ id: 'homoglyphText', label: 'Lookalike letters inside an instruction', weight: 0.1, excerpt: `${confusableLayer.count} lookalike letters` });
  }
  const score = combineWeights(hits.map((h) => h.weight));
  return { score, hits, deob };
}
