import { env } from "../config.js";
import { readFile } from "node:fs/promises";
import { Green, Yellow } from "../misc/console-text.js";
import ip from "ipaddr.js";
import * as cluster from "../misc/cluster.js";

const generateWildcardRegex = rule => {
    var escapeRegex = (str) => str.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
    return new RegExp("^" + rule.split("*").map(escapeRegex).join(".*") + "$");
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
let keys = {};
const ALLOWED_KEYS = new Set(['name', 'ips', 'userAgents', 'limit']);

const validateKeys = (input) => {
    if (typeof input !== 'object' || input === null) {
        throw new Error(`Input is not an object. Received type: ${typeof input}`);
    }

    // Validate keys format
    const invalidKeys = Object.keys(input).filter(x => !UUID_REGEX.test(x));
    if (invalidKeys.length > 0) {
        throw new Error(
            `Key file contains invalid key(s). Invalid keys:\n${invalidKeys.map(key => 
                `- "${key}" (format: ${typeof key === 'string' ? key : JSON.stringify(key)})`
            ).join('\n')}`
        );
    }

    Object.entries(input).forEach(([key, details]) => {
        if (typeof details !== 'object' || details === null) {
            throw new Error(`Key "${key}" is incorrectly configured. Expected object, got: ${typeof details}`);
        }

        const unexpected_key = Object.keys(details).find(k => !ALLOWED_KEYS.has(k));
        if (unexpected_key) {
            throw new Error(`Key "${key}" contains unexpected property: "${unexpected_key}"`);
        }

        if (details.limit && details.limit !== 'unlimited') {
            if (typeof details.limit !== 'number')
                throw new Error(`Key "${key}" contains invalid limit: expected number or "unlimited", got ${typeof details.limit}`);
            else if (details.limit < 1)
                throw new Error(`Key "${key}" contains invalid limit: must be positive, got ${details.limit}`);
        }

        if (details.ips) {
            if (!Array.isArray(details.ips))
                throw new Error(`Key "${key}" contains invalid ips: expected array, got ${typeof details.ips}`);
            
            const invalid_ip = details.ips.find(
                addr => typeof addr !== 'string' || (!ip.isValidCIDR(addr) && !ip.isValid(addr))
            );
            if (invalid_ip) {
                throw new Error(`Key "${key}" contains invalid IP or CIDR range: "${invalid_ip}"`);
            }
        }

        if (details.userAgents) {
            if (!Array.isArray(details.userAgents))
                throw new Error(`Key "${key}" contains invalid userAgents: expected array, got ${typeof details.userAgents}`);
            
            const invalid_ua = details.userAgents.find(ua => typeof ua !== 'string');
            if (invalid_ua) {
                throw new Error(`Key "${key}" contains invalid user agent: ${JSON.stringify(invalid_ua)}`);
            }
        }
    });
}

const formatKeys = (keyData) => {
    const formatted = {};
    for (let key in keyData) {
        const data = keyData[key];
        key = key.toLowerCase();
        formatted[key] = {};
        if (data.limit) {
            if (data.limit === "unlimited") {
                data.limit = Infinity;
            }
            formatted[key].limit = data.limit;
        }
        if (data.ips) {
            formatted[key].ips = data.ips.map(addr => {
                if (ip.isValid(addr)) {
                    const parsed = ip.parse(addr);
                    const range = parsed.kind() === 'ipv6' ? 128 : 32;
                    return [ parsed, range ];
                }
                return ip.parseCIDR(addr);
            });
        }
        if (data.userAgents) {
            formatted[key].userAgents = data.userAgents.map(generateWildcardRegex);
        }
    }
    return formatted;
}

const updateKeys = (newKeys) => {
    keys = formatKeys(newKeys);
}

const loadKeys = async (source) => {
    let updated;
    try {
        if (source.protocol === 'file:') {
            const pathname = source.pathname === '/' ? '' : source.pathname;
            const filePath = decodeURIComponent(source.host + pathname);
            const fileContent = await readFile(filePath, 'utf8');
            try {
                updated = JSON.parse(fileContent);
            } catch (e) {
                throw new Error(`Failed to parse JSON from file ${filePath}. Error: ${e.message}\nContent: ${fileContent.slice(0, 200)}...`);
            }
        } else {
            updated = await fetch(source).then(a => a.json());
        }
        validateKeys(updated);
        cluster.broadcast({ api_keys: updated });
        updateKeys(updated);
    } catch (e) {
        throw new Error(`Failed to load API keys: ${e.message}`);
    }
}

const wrapLoad = (url, initial = false) => {
    loadKeys(url)
    .then(() => {
        if (initial) {
            console.log(`${Green('[✓]')} API keys loaded successfully!`)
        }
    })
    .catch((e) => {
        console.error(`${Yellow('[!]')} Failed loading API keys at ${new Date().toISOString()}`);
        console.error('Error details:', e.message);
        if (e.cause) {
            console.error('Caused by:', e.cause);
        }
    })
}

const err = (reason) => ({ success: false, error: reason });

export const validateAuthorization = (req) => {
    const authHeader = req.get('Authorization');
    if (typeof authHeader !== 'string') {
        return err("missing");
    }
    const [ authType, keyString ] = authHeader.split(' ', 2);
    if (authType.toLowerCase() !== 'api-key') {
        return err("not_api_key");
    }
    if (!UUID_REGEX.test(keyString) || `${authType} ${keyString}` !== authHeader) {
        return err("invalid");
    }
    const matchingKey = keys[keyString.toLowerCase()];
    if (!matchingKey) {
        return err("not_found");
    }
    if (matchingKey.ips) {
        let addr;
        try {
            addr = ip.parse(req.ip);
        } catch {
            return err("invalid_ip");
        }
        const ip_allowed = matchingKey.ips.some(
            ([ allowed, size ]) => {
                return addr.kind() === allowed.kind()
                        && addr.match(allowed, size);
            }
        );
        if (!ip_allowed) {
            return err("ip_not_allowed");
        }
    }
    if (matchingKey.userAgents) {
        const userAgent = req.get('User-Agent');
        if (!matchingKey.userAgents.some(regex => regex.test(userAgent))) {
            return err("ua_not_allowed");
        }
    }
    req.rateLimitKey = keyString.toLowerCase();
    req.rateLimitMax = matchingKey.limit;
    return { success: true };
}

export const setup = (url) => {
    if (cluster.isPrimary) {
        wrapLoad(url, true);
        if (env.keyReloadInterval > 0) {
            setInterval(() => wrapLoad(url), env.keyReloadInterval * 1000);
        }
    } else if (cluster.isWorker) {
        process.on('message', (message) => {
            if ('api_keys' in message) {
                updateKeys(message.api_keys);
            }
        });
    }
}