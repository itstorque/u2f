// a U2F browser implementation in javascript


// we're going to combine website and browser for now!

// ---------------- SECURITY KEY REGISTRATION ----------------

// chrome website asks server for a challenge.
// server responds with a challenge.
function getChallenge() {
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://localhost:3000/challenge');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send();
    });
}

// ClientData data structure:
// - challenge
// - channel id
class ClientData {
    constructor(challenge, channelId) {
        this.challenge = challenge;
        this.channelId = channelId;
    }
}


// chrome website sends origin, & hash(challenge, channel id) to security key
// security key responds with k_pub, attestation cert, signature(hash(challenge, channel i), k_pub, H_k)
function sendClientDataToSecurityKey(origin, challenge, channelId) {
    var clientdata = new ClientData(challenge, channelId);
    // hash clientdata
    var clientdata_hash = CryptoJS.SHA256(JSON.stringify(clientdata));
    // send origin and clientdata_hash to security key
    // returns k_pub, attestation cert, signature(clientdata_hash, k_pub, H_k)
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:3000/challenge');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send(JSON.stringify({
            origin: origin,
            challenge: clientdata_hash
        }));
    });
}

// browser sends CientData, k_pub, H_k, attestation cert, signature to server
// server returns status
function sendResponseToServer(clientdata, k_pub, H_k, attestation_cert, signature) {
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:3000/challenge');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send(JSON.stringify({
            clientdata: clientdata,
            k_pub: k_pub,
            H_k: H_k,
            attestation_cert: attestation_cert,
            signature: signature
        }));
    });
}

// combine getChallenge, sendClientDataToSecurityKey, sendResponseToServer
function registerSecurityKey() {
    getChallenge().then(function (challenge) {
        return sendClientDataToSecurityKey(origin, challenge, channel);
    }).then(function (response) {
        var response_obj = JSON.parse(response);
        var k_pub = response_obj.k_pub;
        var attestation_cert = response_obj.attestation_cert;
        var signature = response_obj.signature;
        return sendResponseToServer(clientdata, k_pub, H_k, attestation_cert, signature);
    }).then(function (response) {
        console.log(response);
    }).catch(function (error) {
        console.log(error);
    });
}

// ---------------- SECURITY KEY AUTHENTICATION ----------------

// client requests to authenticate with server
// server responds with H_k, challenge
function getAuthenticationChallenge() {
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://localhost:3000/authentication');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send();
    });
}

// chrome website sends origin, H_k, & hash(challenge, channel id) to security key
// security key responds with counter, signature(hash(challenge, channel id), counter)
function sendAuthenticationChallengeToSecurityKey(origin, H_k, challenge, channelId) {
    var clientdata = new ClientData(challenge, channelId);
    // hash clientdata
    var clientdata_hash = CryptoJS.SHA256(JSON.stringify(clientdata));
    // send origin, H_k, clientdata_hash to security key
    // returns counter, signature(clientdata_hash, counter)
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:3000/authentication');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send(JSON.stringify({
            origin: origin,
            H_k: H_k,
            challenge: clientdata_hash
        }));
    });
}

// browser sends counter, signature(clientdata_hash, counter), and clientdata to server
// server returns a cookie
function sendAuthenticationResponseToServer(counter, signature, clientdata) {
    return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:3000/authentication');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onload = function () {
            if (xhr.status === 200) {
                resolve(xhr.response);
            } else {
                reject(xhr.statusText);
            }
        };
        xhr.onerror = function () {
            reject(xhr.statusText);
        };
        xhr.send(JSON.stringify({
            counter: counter,
            signature: signature,
            clientdata: clientdata
        }));
    });
}