import express from "express";
import * as grpc from '@grpc/grpc-js';
import {
    connect, Contract, Gateway, Identity, Signer, signers,
    Network, ChaincodeEvent, CloseableAsyncIterable, GatewayError
} from '@hyperledger/fabric-gateway';
import * as crypto from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';
import { TextDecoder } from 'util';
const { initializeApp, applicationDefault, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp, FieldValue, Filter } = require('firebase-admin/firestore');
const ab2str = require('arraybuffer-to-string')
const moment = require('moment');
const asn1js = require('asn1js');
const { createHash } = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
const cors = require('cors');
const morgan = require("morgan");

import * as x509 from "@peculiar/x509";
import e from "express";

const FabricCAServices = require('fabric-ca-client');
const { User, Key } = require('fabric-common');
// const { Gateway, Wallets } = require('fabric-network');

const app = express();

app.use(cors());
const morganFormat = ':remote-addr - :remote-user [:date[iso]] ":method :url HTTP/:http-version" :status :res[content-length] (:response-time ms) ":referrer" ":user-agent"';
app.use(morgan(morganFormat));

const channelName = envOrDefault('CHANNEL_NAME', 'mychannel');
const chaincodeName = envOrDefault('CHAINCODE_NAME', 'token_erc20');

console.log(__dirname);

const serviceAccount = require('/root/fabric-api/key.json');

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

const peerHostList = [
    { org: 'org1.example.com', host: 'localhost:7051', msp: 'Org1MSP'},
    { org: 'org2.example.com', host: 'localhost:9051', msp: 'Org2MSP'},
    { org: 'org3.example.com', host: 'localhost:11051', msp: 'Org3MSP'}];
const caHostList = ['localhost:7054', 'localhost:9054', 'localhost:11054'];

const caURL = 'https://localhost:7054'; // URL of the CA server for org 1

// const mspId = envOrDefault('MSP_ID', 'Org2MSP');
// // Path to crypto materials.
// const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', 'org2.example.com'));
// // Path to user private key directory.
// const keyDirectoryPath = envOrDefault('KEY_DIRECTORY_PATH', path.resolve(cryptoPath, 'users', 'User1@org2.example.com', 'msp', 'keystore'));
// // Path to user certificate.
// const certPath = envOrDefault('CERT_PATH', path.resolve(cryptoPath, 'users', 'User1@org2.example.com', 'msp', 'signcerts', 'cert.pem'));
// // Path to peer tls certificate.
// const tlsCertPath = envOrDefault('TLS_CERT_PATH', path.resolve(cryptoPath, 'peers', 'peer0.org2.example.com', 'tls', 'ca.crt'));
// // Gateway peer endpoint.
// const peerEndpoint = envOrDefault('PEER_ENDPOINT', 'localhost:9051');
// // Gateway peer SSL host name override.
// const peerHostAlias = envOrDefault('PEER_HOST_ALIAS', 'peer0.org2.example.com');

const utf8Decoder = new TextDecoder();
// const assetId = `asset${Date.now()}`;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.post('/', async (req, res) => {
    res.send('Hello from express and typescript');
});

app.post('/init', async (req, res) => {
    const user_id = req.body.user_id;
    const access_token = req.body.access_token;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (access_token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(user.certificate);
        const client = await newGrpcConnection(account.org);

        const gateway = await connectGateway(client, account.user, account.org);

        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Initialize a set of asset data on the ledger using the chaincode 'InitLedger' function.
            await initLedger(contract);
            res.send({
                error: 0,
                data: "Inital Assets done!"
            })
        } catch (error) {
            console.log("init error: ", error);
            gateway.close();
            client.close();
            res.send({
                error: 1,
                data: "Have already initLedger"
            })
        } finally {
            gateway.close();
            client.close();
        }
    }
});

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (username == null || password == null) {
        res.send({
            error: 1,
            errmsg: 'Parameters are missing.'
        });
    } else {
        const passEncode = createHash('sha256')
            .update(password)
            .digest('hex');
        // console.log(username, passEncode);
        const snapshot = await db.collection('user').where('username', '==', username).where('password', '==', passEncode).get();
        let userDetails: any = null;
        // console.log(snapshot);
        snapshot.forEach((doc: any) => {
            userDetails = Object.assign(doc.data(), {
                id: doc.id,
            })
        });
        if (userDetails == null) {
            res.send({
                error: 1,
                errmsg: 'Authorization failure.'
            });
        } else {
            delete userDetails?.password;
            res.send({
                error: 0,
                data: userDetails
            });
        }
        // const ca = new FabricCAServices(caURL);
        // const enrollment = await ca.enroll({ enrollmentID: username, enrollmentSecret: password });
        // const identity = {
        //     credentials: {
        //         certificate: enrollment.certificate,
        //         privateKey: enrollment.key.toBytes(),
        //     },
        //     mspId: 'Org1MSP', // MSP ID of the organization
        //     type: 'X.509',
        // };
        // res.send({
        //     error: 0,
        //     data: userDetails
        // });
    }
});

// app.post('/getUserDetails', async (req, res) => {
//     // const username = req.body.username;
//     // const password = req.body.password;
//     // const identity = await getCredentials(username, password);
//     // const cert = new x509.X509Certificate(identity.credentials.certificate);
//     const identity = await newIdentity();
//     const x509 = new crypto.X509Certificate(identity.credentials);
//     // console.log(cert.subject); // CN=Test, O=PeculiarVentures LLC
//     res.send({
//         error: 0,
//         data: x509
//     });
// });

app.post('/getClientAccountID', async (req, res) => {
    const account_id = req.body.account_id;
    const account = getUserAndOrg(account_id);
    if (account.org == null || account.user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else {
        const client = await newGrpcConnection(account.org);
        const gateway = await connectGateway(client, account.user, account.org);
        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                data: await getClientAccountID(contract)
            });
        } catch (error: any) {
            console.log(error);
            res.send({
                error: 1,
                errmsg: error.cause.details
            });
        } finally {
            gateway.close();
            client.close();
        }
    }
});

app.post('/getBalanceByOrg', async (req, res) => {
    const user_id = req.body.user_id;
    const access_token = req.body.access_token;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (access_token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        let organization: any = null;
        const snapshot = await db.collection('organization').where('access_token', '==', access_token).get();
        snapshot.forEach((doc: any) => {
            organization = doc.data();
        });
        const account = getUserAndOrg(user.certificate);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);
            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);
    
                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);
    
                // Return all the current assets on the ledger.
                const data = await getClientAccountBalance(contract, organization.token_name)
                res.send({
                    error: 0,
                    token_name: organization.token_name,
                    org_name: organization.name,
                    data
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 0,
                    token_name: organization.token_name,
                    org_name: organization.name,
                    data: null
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
})

app.post('/getBalance', async (req, res) => {
    const user_id = req.body.user_id;
    const token = req.body.token;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(user.certificate);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);
            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);
    
                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);
    
                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await getClientAccountBalance(contract, token.toString())
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 0,
                    data: null
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/getBalanceAllToken', async (req, res) => {
    const account_id = req.body.account_id;
    const token = req.body.token;
    if (!account_id || !token) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);
            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);
    
                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);
    
                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await getClientAccountBalance(contract, token.toString())
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 1,
                    errmsg: error.cause.details
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/getAllOffer', async (req, res) => {
    const user_id = req.body.user_id;
    const token = req.body.token;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else {
        let snapshot: any[] = [];
        if (user == null || token == null) {
            snapshot = await db.collection('offers').get();
        } else {
            snapshot = await db.collection('offers').where('from_token', '==', token).get();
        }
        const data: any[] = [];
        snapshot.forEach((doc: any) => {
            const doc_data = doc.data();
            if (doc_data.account_id != user.certificate) {
                data.push(Object.assign(doc.data(), {
                    id: doc.id,
                    from_value: parseInt(doc_data.from_value),
                    to_value: parseInt(doc_data.to_value),
                }));
            }
        });
        res.send({
            error: 0,
            data
        });
    }
});

app.post('/getMyOffer', async (req, res) => {
    const user_id = req.body.user_id;
    const token = req.body.token;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const data: any[] = [];
        const snapshot = await db.collection('offers').where('account_id', '==', user.certificate).where('from_token', '==', token).get();
        snapshot.forEach((doc: any) => {
            const doc_data = doc.data();
            data.push(Object.assign(doc.data(), {
                id: doc.id,
                from_value: parseInt(doc_data.from_value),
                to_value: parseInt(doc_data.to_value),
            }));
        });
        res.send({
            error: 0,
            data
        });
    }
});

app.post('/deleteOffer', async (req, res) => {
    const doc_id = req.body.id;
    if (doc_id != null) {
        await db.collection('offers').doc(doc_id).delete();
    }
    res.send({
        error: 0
    });
})

app.post('/createOffer', async (req, res) => {
    let account_id = req.body.account_id;
    let from_value = req.body.from_value;
    let from_token = req.body.from_token;
    let to_value = req.body.to_value;
    let to_token = req.body.to_token;

    if (from_value == undefined || from_token == undefined || to_value == undefined || to_token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);
            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);

                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);

            } catch (error: any) {
                console.log(error);
            } finally {
                gateway.close();
                client.close();
            }
            if (account_id == undefined) {
                res.send({
                    error: 1,
                    errmsg: "Can't find account id."
                });
            } else {
                // const identity = await newIdentity();
                // const x509 = new crypto.X509Certificate(identity.credentials);
                // const accountDetails = x509.toLegacyObject();
                // const org = accountDetails.subject.O;
                // const user = accountDetails.subject.CN;
                const docRef = db.collection('offers').doc();
                await docRef.set({
                    account_id,
                    from_token,
                    from_value,
                    to_token,
                    to_value,
                    org: account.org,
                    user: account.user,
                    created: moment().format("YYYY-MM-DD HH:mm:ss")
                });
                res.send({
                    error: 0
                });
            }
        }
    }
});

app.post('/getAllTokens', async (req, res) => {
    const user_id = req.body.user_id;
    if (!user_id) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const user = await getUserDetails(user_id);
        if (user == null) {
            res.send({
                error: 1,
                errmsg: `Can't find offer id ${user_id}`
            });
        } else {
            const account_id = user.certificate;
            const account = getUserAndOrg(account_id);
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);
            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);
    
                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);
    
                // Return all the current assets on the ledger.
                const tokenName = await getAllTokens(contract);
                const data = tokenName.split(',');
                res.send({
                    error: 0,
                    data
                });
    
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/getAllTransfer', async (req, res) => {
    let account_id = req.body.account_id;
    const account = getUserAndOrg(account_id);
    if (account.org == null || account.user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else {
        const client = await newGrpcConnection(account.org);

        const gateway = await connectGateway(client, account.user, account.org);

        try {
            const network = gateway.getNetwork(channelName);
            const contract = network.getContract(chaincodeName);
            const token_list = await getAllTokens(contract);
            const all_transection = [];
            for (let i = 0; i < token_list.length; i++) {
                const token = token_list[i]
                const data = await getWalletHistory(contract, token);
                all_transection.push(...data.map((row: any) => Object.assign(row, { token })))
            }
            const all_transfer: any = [];
            all_transection.forEach(transection => {
                const transfer = all_transfer.find((row: any) => row.tx_id == transection.tx_id);
                if (transfer != undefined) {
                    if (transection.tx_amount < 0) {
                        Object.assign(transfer, { from: transection })
                    } else {
                        Object.assign(transfer, { to: transection })
                    }
                } else {
                    const data = {
                        tx_id: transection.tx_id,
                        from: transection.tx_amount < 0 ? transection : null,
                        to: transection.tx_amount > 0 ? transection : null
                    }
                    all_transfer.push(data);
                }
            });
            res.send({
                error: 0,
                data: all_transfer
            });
        } finally {
            gateway.close();
            client.close();
        }
    }
});

app.post('/getUserPoints', async (req, res) => {
    const access_token = req.body.access_token;
    const org_token = req.body.org_token;
    if (!access_token || !org_token) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        let organization: any = null;
        const snapshot = await db.collection('organization').where('access_token', '==', access_token).get();
        snapshot.forEach((doc: any) => {
            organization = doc.data();
        });
        if (organization == null) {
            res.send({
                error: 1,
                errmsg: "Can't get organization details"
            });
        } else {
            try {
                const postData = {
                    token: org_token,
                };
                const url = organization.url_ex_account_points;
                const response = await axios.post(url, postData);
                let data: any = null;
                if (response.data != null) {
                    data = response.data.data;
                    Object.assign(data, { org_name: organization.name });
                }
                res.send({
                    error: 0,
                    data
                });
            } catch (error) {
                console.log(error);
                res.send({
                    error: 1,
                    errmsg: error
                });
            }
        }
    }
})

app.post('/deposit', async (req, res) => {
    const user_id = req.body.user_id;
    const user_org_token = req.body.user_org_token;
    const token = req.body.token;
    let value = req.body.value;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(user.certificate);
        let data: any = null;
        const snapshot = await db.collection('organization').where('token_name', '==', token).get();
        snapshot.forEach((doc: any) => {
            data = doc.data();
        });
        if (data == null) {
            res.send({
                error: 1,
                errmsg: "Can't get organization details"
            });
        } else {
            // todo add function check token in my offer list and change remain amount
            const postData = {
                token: user_org_token,
                value
            };
            try {
                const url = data.url_deposit;
                const response = await axios.post(url, postData);
                let points_list: any[] = [];
                if (response.data != null) {
                    points_list = response.data.points_list;
                }

                if (points_list != null && points_list.length > 0) {
                    // Check exchange account points

                    const client = await newGrpcConnection(account.org);
                    value = value.toString();

                    const gateway = await connectGateway(client, account.user, account.org);

                    try {

                        //todo add check and check owner api from app
                        const network = gateway.getNetwork(channelName);
                        const contract = network.getContract(chaincodeName);

                        // Return all the current assets on the ledger.
                        res.send({
                            error: 0,
                            data: await mint(contract, token, value, JSON.stringify(points_list))
                        });
                    } catch (error2: any) {
                        console.log(error2.cause.details);
                        res.send({
                            error: 1,
                            errmsg: error2.cause.details
                        });
                    } finally {
                        gateway.close();
                        client.close();
                    }
                } else {
                    res.send({
                        error: 1,
                        errmsg: "Can't get user points"
                    });
                }
            } catch (error: any) {
                console.log(error.message);
                res.send({
                    error: 1,
                    errmsg: error.message
                });
            }
            
        }
    }
});

app.post('/withdraw', async (req, res) => {
    const user_id = req.body.user_id;
    const user_org_token = req.body.user_org_token;
    let token = req.body.token;
    let value = req.body.value;
    const user = await getUserDetails(user_id);
    if (user == null) {
        res.send({
            error: 1,
            errmsg: "Authorization failure."
        });
    } else if (token == null) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(user.certificate);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            let data: any = null;
            const snapshot = await db.collection('organization').where('token_name', '==', token).get();
            snapshot.forEach((doc: any) => {
                data = doc.data();
            });
            if (data == null) {
                res.send({
                    error: 1,
                    errmsg: "Can't get organization details"
                });
            } else {
                // Call 3rd party api to check enough points and format to poitns_list and transfer points to exchange account
                const postData = {
                    token: user_org_token,
                    value
                };
                const url = data.url_withdraw;
                let error: any = null;
                try {
                    const response = await axios.post(url, postData);
                    if (response.data != null) {
                        error = response.data.error;
                    }
                } catch (error) {
                    console.log(error);
                    res.send({
                        error: 1,
                        errmsg: "Can't withdraw points"
                    });
                }

                if (error == 0) {
                    const client = await newGrpcConnection(account.org);
                    value = value.toString();
    
                    const gateway = await connectGateway(client, account.user, account.org);
    
                    try {
    
                        //todo add check and check owner api from app
                        const network = gateway.getNetwork(channelName);
                        const contract = network.getContract(chaincodeName);
    
                        // Return all the current assets on the ledger.
                        res.send({
                            error: 0,
                            data: await withdraw(contract, token, value)
                        });
                    } catch (error: any) {
                        console.log(error);
                        res.send({
                            error: 1,
                            errmsg: error.cause.details
                        });
                    } finally {
                        gateway.close();
                        client.close();
                    }
                } else {
                    res.send({
                        error: 1,
                        errmsg: "Can't withdraw points"
                    });
                }
            }
        }
    }
});

app.post('/acceptOffer', async (req, res) => {
    let account_id = req.body.account_id;
    const offer_id = req.body.offer_id;
    if (offer_id == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const snapshot = await db.collection('offers').where('__name__', '==', offer_id).get();
            if (snapshot.docs.length == 0) {
                res.send({
                    error: 1,
                    errmsg: `Can't find offer id ${offer_id}`
                });
            } else {
                // Backward from to between user who create offer and accept offer
                const doc = snapshot.docs[0].data();
                const from_account_id = doc.account_id;
                const from_value = doc.to_value;
                const from_token = doc.to_token;
                const to_value = doc.from_value;
                const to_token = doc.from_token;
                const client = await newGrpcConnection(account.org);
                const gateway = await connectGateway(client, account.user, account.org);

                try {
                    // console.log(account_id, from_value, to_value, from_token, to_token);
                    // Get a network instance representing the channel where the smart contract is deployed.
                    const network = gateway.getNetwork(channelName);

                    // Get the smart contract from the network.
                    const contract = network.getContract(chaincodeName);

                    // Return all the current assets on the ledger.
                    res.send({
                        error: 0,
                        data: await transferBalanceAsync(contract, from_account_id, from_value, to_value, from_token, to_token)
                    });
                    await db.collection('offers').doc(offer_id).delete();
                } catch (error: any) {
                    console.log(error);
                    const errmsg = error == null ? "" : error.cause.details;
                    res.send({
                        error: 1,
                        errmsg
                    });
                } finally {
                    gateway.close();
                    client.close();
                }
            }
        }
    }
});

app.post('/getHistory', async (req, res) => {
    let token = req.body.token;
    let account_id = req.body.account_id;

    if (token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            token = token.toString();
            const gateway = await connectGateway(client, account.user, account.org);

            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);

                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);

                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await getWalletHistory(contract, token)
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 1,
                    errmsg: error.cause.details
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/getHistoryWithSource', async (req, res) => {
    let token = req.body.token;
    let account_id = req.body.account_id;

    if (token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            token = token.toString();
            const gateway = await connectGateway(client, account.user, account.org);

            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);

                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);

                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await getHistoryWithSource(contract, token)
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 1,
                    errmsg: error.cause.details
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/getBlockDetails', async (req, res) => {
    let number = req.body.number;
    let account_id = req.body.account_id;

    if (number == undefined) {
        res.send({
            error: 0,
            data: null
        });
    } else {
        const account = getUserAndOrg(account_id);
        if (account.org == null || account.user == null) {
            res.send({
                error: 1,
                errmsg: "Authorization failure."
            });
        } else {
            const client = await newGrpcConnection(account.org);
            const gateway = await connectGateway(client, account.user, account.org);

            try {
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);

                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await getBlockDetails(network, number.toString())
                });
            } catch (error: any) {
                console.log(error);
                res.send({
                    error: 1,
                    errmsg: error
                });
            } finally {
                gateway.close();
                client.close();
            }
        }
    }
});

app.post('/register', async (req, res) => {

    try {
        // Create a new CA client for interacting with the CA server
        const caURL = 'https://localhost:7054'; // URL of the CA server
        const ca = new FabricCAServices(caURL);

        // Enroll the admin user
        const adminId = 'admin';
        const adminSecret = 'adminpw';
        const enrollment = await ca.enroll({ enrollmentID: adminId, enrollmentSecret: adminSecret });
        const identity = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: 'Org1MSP', // MSP ID of the organization
            type: 'X.509',
        };

        const user = new User(adminId);
        await user.setEnrollment(enrollment.key, enrollment.certificate, 'Org1MSP');

        // console.log(user);

        // Register the new user
        const userId = 'user2';
        const registrationRequest = {
            enrollmentID: userId,
            enrollmentSecret: "user2pw",
            affiliation: 'org1.example.com', // Affiliation within the organization
            role: 'client', // Role of the user
            attrs: [{ name: 'role', value: 'member' }], // Additional attributes
        };
        const secret = await ca.register(registrationRequest, user);
        console.log(`Successfully registered user ${userId} with secret ${secret}`);

        res.send({
            error: 0
        });
    } catch (error) {
        console.error(`Failed to register user: ${error}`);
        process.exit(1);
    }
});

const port = process.env.PORT || 3001

app.listen(port, () => console.log(`App listening on PORT ${port}`))

async function connectGateway(client: any, user: string, org: string): Promise<Gateway> {
    return connect({
        client,
        // identity: { mspId, credentials: Buffer.from(certificate) },
        identity: await newIdentity(user, org),
        signer: await newSigner(user, org),
        // Default timeouts for different gRPC calls
        evaluateOptions: () => {
            return { deadline: Date.now() + 5000 }; // 5 seconds
        },
        endorseOptions: () => {
            return { deadline: Date.now() + 15000 }; // 15 seconds
        },
        submitOptions: () => {
            return { deadline: Date.now() + 5000 }; // 5 seconds
        },
        commitStatusOptions: () => {
            return { deadline: Date.now() + 60000 }; // 1 minute
        },
    });
}

function envOrDefault(key: string, defaultValue: string): string {
    return process.env[key] || defaultValue;
}

async function initLedger(contract: Contract): Promise<void> {
    console.log('\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger');

    await contract.submitTransaction('Initialize', "token1", "TK1");
    await contract.submitTransaction('Initialize', 'token2', "TK2");
    await contract.submitTransaction('Initialize', 'token3', "TK3");

    console.log('*** Transaction committed successfully');
}

async function getClientAccountID(contract: Contract): Promise<any> {
    console.log('\n--> Evaluate Transaction: ClientAccountID');
    const resultBytes = await contract.evaluateTransaction('ClientAccountID');
    const resultJson = utf8Decoder.decode(resultBytes);
    // const result = JSON.parse(resultJson);
    return resultJson;
}

async function getClientAccountBalance(contract: Contract, token: string): Promise<any> {
    console.log('\n--> Evaluate Transaction: ClientAccountID');
    const resultBytes = await contract.evaluateTransaction('ClientAccountBalance', token);
    const resultJson = utf8Decoder.decode(resultBytes);
    return JSON.parse(resultJson);
}

/**
 * Evaluate a transaction to query ledger state.
 */
async function getAllTokens(contract: Contract): Promise<any> {
    console.log('\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger');

    const resultBytes = await contract.evaluateTransaction('TokenNameList');

    const resultJson = utf8Decoder.decode(resultBytes);
    // return JSON.parse(resultJson);
    return resultJson;
}
/**
 * Submit a transaction synchronously, blocking until it has been committed to the ledger.
 */
async function mint(contract: Contract, token: string, value: string, points_list: string): Promise<string> {
    console.log('\n--> Submit Transaction: Mint to create token value and add to creater');

    await contract.submitTransaction(
        'Mint',
        value,
        token,
        points_list
    );

    console.log('*** Transaction committed successfully');
    return "Transaction committed successfully";

}

/**
 * Submit a transaction synchronously, blocking until it has been committed to the ledger.
 */
async function withdraw(contract: Contract, token: string, value: string): Promise<string> {
    console.log('\n--> Submit Transaction: Withdraw to decease token value and brun from platform');

    await contract.submitTransaction(
        'Withdraw',
        value,
        token
    );

    console.log('*** Transaction committed successfully');
    return "Transaction committed successfully";

}

/**
 * Submit transaction asynchronously, allowing the application to process the smart contract response (e.g. update a UI)
 * while waiting for the commit notification.
 */
async function transferAssetAsync(contract: Contract, assetId: string, newOwner: string): Promise<string> {
    console.log('\n--> Async Submit Transaction: TransferAsset, updates existing asset owner');

    const commit = await contract.submitAsync('TransferAsset', {
        arguments: [assetId, newOwner],
    });
    const oldOwner = utf8Decoder.decode(commit.getResult());

    console.log(`*** Successfully submitted transaction to transfer ownership from ${oldOwner} to Saptha`);
    console.log('*** Waiting for transaction commit');

    const status = await commit.getStatus();
    if (!status.successful) {
        throw new Error(`Transaction ${status.transactionId} failed to commit with status code ${status.code}`);
    }

    console.log('*** Transaction committed successfully');
    return "Transaction committed successfully";
}

async function transferBalanceAsync(contract: Contract, toAddressId: string, fromValue: string, toValue: string, fromToken: string, toToken: string): Promise<string> {
    console.log('\n--> Async Submit Transaction: TransferBalance, updates wallet balance');

    console.log(toAddressId, fromValue.toString(), toValue.toString(), fromToken, toToken);

    const commit = await contract.submitAsync('Transfer', {
        arguments: [toAddressId, fromValue.toString(), toValue.toString(), fromToken, toToken],
    });
    const oldOwner = utf8Decoder.decode(commit.getResult());

    console.log(`*** Successfully submitted transaction to transfer balance from ${oldOwner} to  ${toAddressId} from_value ${fromValue} token ${fromToken}`);
    console.log('*** Waiting for transaction commit');

    const status = await commit.getStatus();
    if (!status.successful) {
        throw new Error(`Transaction ${status.transactionId} failed to commit with status code ${status.code}`);
    }

    console.log('*** Transaction committed successfully');
    return "Transaction committed successfully";
}

async function getWalletHistory(contract: Contract, token: string): Promise<any> {
    console.log('\n--> Evaluate Transaction: ReadAsset, function returns asset attributes');

    const resultBytes = await contract.evaluateTransaction('GetHistoryForKey', token);

    const resultJson = utf8Decoder.decode(resultBytes);
    const result = JSON.parse(resultJson);
    console.log('*** Result:', result);
    return result;
}

async function getHistoryWithSource(contract: Contract, token: string): Promise<any> {
    console.log('\n--> Evaluate Transaction: ReadAsset, function returns asset attributes');

    const resultBytes = await contract.evaluateTransaction('GetHistoryForKeyWithSource', token);

    const resultJson = utf8Decoder.decode(resultBytes);
    const result = JSON.parse(resultJson);
    console.log('*** Result:', result);
    return result;
}

async function startEventListening(network: Network): Promise<CloseableAsyncIterable<ChaincodeEvent>> {
    console.log('\n*** Start chaincode event listening');

    const events = await network.getChaincodeEvents(chaincodeName);

    void readEvents(events); // Don't await - run asynchronously
    return events;
}

async function getBlockDetails(network: Network, blockNum: string): Promise<any> {
    console.log('\n*** Start get block deteails by number');

    const contract = network.getContract("qscc");

    let resultBytes = await contract.evaluateTransaction("GetBlockByNumber", channelName, blockNum);

    // const resultJson = BlockDecoder.decode(Buffer.from(resultBytes));
    // // const resultDecoded = JSON.stringify(fabproto6.common.Block.decode(resultBytes));
    // // console.log('queryBlock', Buffer.from(resultBytes));
    // const hex_previous_hash = ab2str(resultJson.header.previous_hash, 'hex');
    // const hex_data_hash = ab2str(resultJson.header.data_hash, 'hex');

    // resultJson.header.previous_hash = ab2str(resultJson.header.previous_hash, 'base64');
    // resultJson.header.data_hash = ab2str(resultJson.header.data_hash, 'base64');
    // resultJson.header.number = resultJson.header.number.low;

    const resultJson = utf8Decoder.decode(resultBytes);
    // const result = JSON.parse(resultJson);
    // console.log('*** Result:', resultJson);

    return resultJson;
}

async function readEvents(events: CloseableAsyncIterable<ChaincodeEvent>): Promise<void> {
    try {
        for await (let event of events) {
            console.log('\n*** Receive event');

            const payload = parseJson(event.payload);
            console.log(`\n<-- Chaincode event received: ${event.eventName} -`, payload);
        }
    } catch (error: unknown) {
        // Ignore the read error when events.close() is called explicitly
        if (!(error instanceof GatewayError) || error.code !== grpc.status.CANCELLED) {
            throw error;
        }
    }
}

function parseJson(jsonBytes: Uint8Array): unknown {
    const json = utf8Decoder.decode(jsonBytes);
    return JSON.parse(json);
}

function getUserAndOrg(account_id: string) {
    const myArray = account_id.split('::');
    let user = '';
    let org = '';
    myArray[1].split('/').forEach((row: string) => {
        const value = row.split('=');
        if (value[0] == 'CN') {
            user = value[1];
        }
    });
    myArray[2].split('/').forEach((row: string) => {
        const value = row.split('=');
        if (value[0] == 'O') {
            org = value[1];
        }
    });
    return { user, org }
}

async function getUserDetails(user_id: string): Promise<any> {
    const snapshot = await db.collection('user').where('__name__', '==', user_id).get();
    let user = null;
    snapshot.forEach((doc: any) => {
        user = doc.data();
    });
    return user;
}

async function newGrpcConnection(orgName: string): Promise<grpc.Client> {
    let host = peerHostList.find(row => row.org == orgName)?.host;
    if (host == undefined) {
        host = '';
    }
    // Path to crypto materials.
    const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', orgName));
    const tlsCertPath = envOrDefault('TLS_CERT_PATH', path.resolve(cryptoPath, 'peers', 'peer0.' + orgName, 'tls', 'ca.crt'));
    const peerEndpoint = envOrDefault('PEER_ENDPOINT', host);
    const peerHostAlias = envOrDefault('PEER_HOST_ALIAS', 'peer0.' + orgName);
    const tlsRootCert = await fs.readFile(tlsCertPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    return new grpc.Client(peerEndpoint, tlsCredentials, {
        'grpc.ssl_target_name_override': peerHostAlias,
    });
}

async function newIdentity(user: string, orgName: string): Promise<Identity> {
    const camelUser = user.charAt(0).toUpperCase() + user.slice(1).toLowerCase();
    let msp = peerHostList.find(row => row.org == orgName)?.msp;
    if (msp == undefined) {
        msp = '';
    }
    const mspId = envOrDefault('MSP_ID', msp);
    const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', orgName));
    const certPath = envOrDefault('CERT_PATH', path.resolve(cryptoPath, 'users', camelUser + '@' + orgName, 'msp', 'signcerts', 'cert.pem'));
    const credentials = await fs.readFile(certPath);
    return { mspId, credentials };
}

async function newSigner(user: string, orgName: string): Promise<Signer> {
    const camelUser = user.charAt(0).toUpperCase() + user.slice(1).toLowerCase();
    const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', orgName));
    const keyDirectoryPath = envOrDefault('KEY_DIRECTORY_PATH', path.resolve(cryptoPath, 'users', camelUser + '@' + orgName, 'msp', 'keystore'));
    const files = await fs.readdir(keyDirectoryPath);
    const keyPath = path.resolve(keyDirectoryPath, files[0]);
    const privateKeyPem = await fs.readFile(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return signers.newPrivateKeySigner(privateKey);
}

async function getCredentials(username: String, password: String) {
    const ca = new FabricCAServices(caURL);
    const enrollment = await ca.enroll({ enrollmentID: username, enrollmentSecret: password });
    return {
        credentials: {
            certificate: enrollment.certificate,
            privateKey: enrollment.key.toBytes(),
        },
        mspId: 'Org1MSP', // MSP ID of the organization
        type: 'X.509',
    };
}
