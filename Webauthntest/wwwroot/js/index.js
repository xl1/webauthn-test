//@ts-check

const $ = id => document.getElementById(id);

function post(url, data = {}) {
    return fetch(url, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'x-requested-with': 'fetch'
        },
        credentials: 'same-origin',
        body: JSON.stringify(data)
    }).then(r => r.json());
}

const convert = {
    binary: {
        toArrayBuffer(binary) {
            return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
        },
        toBase64: binary => btoa(binary)
    },
    arrayBuffer: {
        toBinary(ab) {
            return String.fromCharCode(...new Uint8Array(ab));
        },
        toBase64(ab) {
            return btoa(this.toBinary(ab));
        }
    },
    base64: {
        toBinary: b64 => atob(b64),
        toArrayBuffer: b64 => convert.binary.toArrayBuffer(atob(b64))
    }
};

function showMessage(msg) {
    $('message').innerText = msg;
}

async function makeCredential(name) {
    const response = await post(`/api/credentials/challenge?name=${encodeURIComponent(name)}`);
    const challenge = convert.base64.toArrayBuffer(response.challenge);
    const publicKey = {
        rp: {
            id: response.relyingPartyId,
            name: response.relyingParty,
        },
        user: {
            id: challenge,
            name: `${name}@${location.host}`,
            displayName: name,
        },
        challenge: challenge,
        pubKeyCredParams: [{
            type: /**@type {PublicKeyCredentialType}*/('public-key'),
            alg: -7 // ES256
        }],
        timeout: 60000,
        attestation: /**@type {AttestationConveyancePreference}*/("direct")
    };

    showMessage('please insert your security key');

    const cred = /**@type {PublicKeyCredential}*/(await navigator.credentials.create({ publicKey }));
    const {
        attestationObject,
        clientDataJSON
    } = /**@type {AuthenticatorAttestationResponse}*/(cred.response);
    const data = {
        id: cred.id,
        rawId: convert.arrayBuffer.toBase64(cred.rawId),
        type: cred.type,
        attestation: convert.arrayBuffer.toBase64(attestationObject),
        clientData: convert.arrayBuffer.toBase64(clientDataJSON),
    };
    console.dir(data);
    console.log(convert.arrayBuffer.toBinary(clientDataJSON));
    const registration = await post('/api/credentials/register', data);

    // TODO
    showMessage('registered');
}

async function verify(name) {
    const response = await post(`/api/credentials/assertion?name=${encodeURIComponent(name)}`);
    const challenge = convert.base64.toArrayBuffer(response.challenge);
    const publicKey = {
        rpId: response.relyingPartyId,
        challenge: challenge,
        allowCredentials: response.allowCredentials.map(c => ({
            type: c.type,
            id: convert.base64.toArrayBuffer(c.id)
        })),
        timeout: 60000,
    };

    showMessage('please insert your security key');

    const cred = /**@type {PublicKeyCredential}*/(await navigator.credentials.get({ publicKey }));
    const {
        authenticatorData,
        clientDataJSON,
        signature
    } = /**@type {AuthenticatorAssertionResponse}*/(cred.response);
    const data = {
        id: cred.id,
        rawId: convert.arrayBuffer.toBase64(cred.rawId),
        type: cred.type,
        authData: convert.arrayBuffer.toBase64(authenticatorData),
        clientData: convert.arrayBuffer.toBase64(clientDataJSON),
        signature: convert.arrayBuffer.toBase64(signature),
    };
    console.dir(data);
    console.log(convert.arrayBuffer.toBinary(clientDataJSON));
    const assertion = await post('/api/credentials/verify', data);

    // TODO
    showMessage('verified');
}

$('registerButton').addEventListener('click', e => {
    e.preventDefault();
    showMessage('');
    const username = /**@type {HTMLInputElement}*/($('username')).value;
    makeCredential(username).then(console.log);
}, false);

$('verifyButton').addEventListener('click', e => {
    e.preventDefault();
    showMessage('');
    const username = /**@type {HTMLInputElement}*/($('username')).value;
    verify(username).then(console.log);
}, false);
