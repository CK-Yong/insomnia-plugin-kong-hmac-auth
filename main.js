// For help writing plugins, visit the documentation to get started:
//   https://docs.insomnia.rest/insomnia/introduction-to-plugins

module.exports.templateTags = [{
    name: 'hmacAuthHeader',
    displayName: 'Insert HMAC Auth Headers',
    description: 'Generate a HMAC Auth Header to use with Kong HMAC Auth plugin. This will also insert Date and Digest headers if necessary.',
    args: [
        {
            displayName: 'Username',
            description: 'The username to use for HMAC authentication.',
            type: 'string',
            defaultValue: ''
        },
        {
            displayName: 'Secret',
            description: 'The secret to use for HMAC authentication.',
            type: 'string',
            defaultValue: ''
        },
        {
            displayName: 'Timestamp',
            description: 'The timestamp to use. Leave empty to use the current time.',
            type: 'string',
            defaultValue: null,
            placeholder: new Date().toUTCString()
        },
        {
            displayName: 'Algorithm',
            description: 'Which hash algorithm to use for HMAC authentication.',
            type: 'enum',
            defaultValue: 'hmac-sha256',
            options: [
                {
                    displayName: 'HMAC-SHA1',
                    value: 'hmac-sha1'
                },
                {
                    displayName: 'HMAC-SHA256',
                    value: 'hmac-sha256'
                },
                {
                    displayName: 'HMAC-SHA384',
                    value: 'hmac-sha384'
                },
                {
                    displayName: 'HMAC-SHA512',
                    value: 'hmac-sha512'
                }
            ]
        },
        {
            displayName: 'HTTP Version',
            description: 'The HTTP version to use for the request.',
            type: 'enum',
            defaultValue: 'HTTP/1.1',
            options: [
                {
                    displayName: 'HTTP/1.1',
                    value: 'HTTP/1.1'
                },

                {
                    displayName: 'HTTP/2',
                    value: 'HTTP/2'
                },
            ]
        },
        {
            displayName: 'Headers',
            description: 'The headers to include in the HMAC Auth request, in lower-case, separated by spaces.',
            type: 'string',
            defaultValue: 'date request-line digest',
            placeholder: 'date request-line digest'
        }
    ],
    async run(context, username, secret, timestamp, algorithm, httpVersion, headers) {
        await context.store.setItem("username", username);
        await context.store.setItem("secret", secret);
        await context.store.setItem("ts", timestamp);
        await context.store.setItem("alg", algorithm);
        await context.store.setItem("httpVer", httpVersion);
        await context.store.setItem("headers", headers);

        return 'No preview available. Header will be added when the request is sent.';
    }
}];


module.exports.requestHooks = [
    async context => {
        const crypto = require('crypto');

        if (!context.request.hasHeader("Authorization")) {
            console.debug('No Authorization header found. HMAC Auth plugin is not active.')
            return;
        }

        var username = await context.store.getItem("username");
        var secret = await context.store.getItem("secret");
        var timestamp = await context.store.getItem("ts");
        var algorithm = await context.store.getItem("alg");
        var httpVersion = await context.store.getItem("httpVer");
        var headerStr = await context.store.getItem("headers");

        if (!headerStr || headerStr.length === 0) {
            headerStr = 'date request-line digest';
        }

        if (!timestamp) {
            timestamp = new Date().toUTCString();
            console.debug('Using current timestamp:', timestamp);
        }

        if (!username || !secret || !timestamp || !algorithm) {
            console.debug('HMAC Auth plugin is not active. Missing required data.')
            return;
        }

        var headers = headerStr.split(' ');
        console.debug('Headers to sign:', headers);
        var signingStringArray = [];
        for (var header of headers) {
            if (header === 'date') {
                signingStringArray.push(`date: ${timestamp}`);
                context.request.setHeader("Date", timestamp);
                console.debug('Added Date header:', timestamp);
                continue;
            }

            if (header === 'request-line') {
                var url = new URL(context.request.getUrl());
                var requestLine = `${context.request.getMethod().toUpperCase()} ${url.pathname}${url.search} ${httpVersion}`;
                signingStringArray.push(requestLine);
                console.debug('Added Request-Line header to signing string', requestLine);
                continue;
            }

            if (header === '@request-target') {
                var url = new URL(context.request.getUrl());
                var requestTarget = `${context.request.getMethod().toLowerCase()} ${url.pathname}${url.search}`;
                signingStringArray.push(requestTarget);
                console.debug('Added Request-Target header to signing string', requestTarget);
                continue; 
            }

            if (header === 'digest') {
                var bodyDigest = crypto.createHash("sha256").update(context.request.getBody().text).digest("base64");
                signingStringArray.push(`digest: SHA-256=${bodyDigest}`);
                context.request.setHeader("Digest", `SHA-256=${bodyDigest}`);
                console.debug('Added Digest header:', `SHA-256=${bodyDigest}`);
                continue;
            }

            // Not recognised header, but will be adding it as is.
            signingStringArray.push(`${header}: ${context.request.getHeader(header)}`);
        }

        var signingString = signingStringArray.join('\n');

        console.debug(signingString);

        var algKey = algorithm.replace('hmac-', '');
        var signature = crypto.createHmac(algKey, secret).update(signingString).digest("base64");

        context.request.setHeader("Authorization", `hmac username="${username}", algorithm="${algorithm}", headers="${headerStr}", signature="${signature}"`);
    }
];