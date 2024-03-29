import express from "express";
import * as grpc from '@grpc/grpc-js';
import {
    connect, Contract, Gateway, Identity, Signer, signers,
    Network, ChaincodeEvent, CloseableAsyncIterable, GatewayError
} from '@hyperledger/fabric-gateway';
// import { BlockDecoder } from 'fabric-common';
import * as fabproto6 from 'fabric-protos';
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

const FabricCAServices = require('fabric-ca-client');
const { User } = require('fabric-common');
// const { Gateway, Wallets } = require('fabric-network');

const app = express();

const channelName = envOrDefault('CHANNEL_NAME', 'mychannel');
const chaincodeName = envOrDefault('CHAINCODE_NAME', 'token_erc20');

console.log(__dirname);

const serviceAccount = require('/root/fabric-api/key.json');

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

const mspId = envOrDefault('MSP_ID', 'Org1MSP');
// Path to crypto materials.
const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', 'org1.example.com'));
// Path to user private key directory.
const keyDirectoryPath = envOrDefault('KEY_DIRECTORY_PATH', path.resolve(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'keystore'));
// Path to user certificate.
const certPath = envOrDefault('CERT_PATH', path.resolve(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'signcerts', 'cert.pem'));
// Path to peer tls certificate.
const tlsCertPath = envOrDefault('TLS_CERT_PATH', path.resolve(cryptoPath, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt'));
// Gateway peer endpoint.
const peerEndpoint = envOrDefault('PEER_ENDPOINT', 'localhost:7051');
// Gateway peer SSL host name override.
const peerHostAlias = envOrDefault('PEER_HOST_ALIAS', 'peer0.org1.example.com');

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

app.get('/', async (req, res) => {
    res.send('Hello from express and typescript');
});

app.get('/init', async (req, res) => {
    const client = await newGrpcConnection();

    const gateway = await connectGateway(client);

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
});

app.get('/initMint', async (req, res) => {
    const client = await newGrpcConnection();

    const gateway = await connectGateway(client);

    try {
        // Get a network instance representing the channel where the smart contract is deployed.
        const network = gateway.getNetwork(channelName);

        // Get the smart contract from the network.
        const contract = network.getContract(chaincodeName);

        // Initialize a set of asset data on the ledger using the chaincode 'InitMint' function.
        await initMint(contract);
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
            data: "Have already initMint"
        })
    } finally {
        gateway.close();
        client.close();
    }
});

app.get('/testTrans', async (req, res) => {
    let n = req.query.n?.toString();
    const client = await newGrpcConnection();

    if (n == null) {
        n = '1';
    }

    const gateway = await connectGateway(client);

    try {
        // Get a network instance representing the channel where the smart contract is deployed.
        const network = gateway.getNetwork(channelName);

        // Get the smart contract from the network.
        const contract = network.getContract(chaincodeName);

        // Initialize a set of asset data on the ledger using the chaincode 'InitMint' function.
        // if (parseInt(n) > 10) {
        //     for (let i = 0; i < Math.floor(parseInt(n) / 10); i++) {
        //         await testTrans(contract, '10');
        //     }
        //     if (parseInt(n) % 10 > 0) {
        //         await testTrans(contract, (parseInt(n) % 10).toString());
        //     }
        // } else {
        await testTrans(contract, n);
        // }
        
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
            data: "Have already initMint"
        })
    } finally {
        gateway.close();
        client.close();
    }
});

app.get('/getUserDetails', async (req, res) => {
    const identity = await newIdentity();
    const x509 = new crypto.X509Certificate(identity.credentials);
    res.send({
        error: 0,
        data: x509.toLegacyObject()
    });
});

app.get('/getClientAccountID', async (req, res) => {
    const client = await newGrpcConnection();
    const gateway = await connectGateway(client);
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
});

app.get('/getBalance', async (req, res) => {
    const token = req.query.token;
    if (token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        const gateway = await connectGateway(client);
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
});

app.get('/getAllOffer', async (req, res) => {
    // const snapshot  = await db.collection('orders').where('__name__', '==', 'offer').get();
    const snapshot = await db.collection('offers').get();
    const data: any[] = [];
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
});

app.post('/createOffer', async (req, res) => {
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
        const client = await newGrpcConnection();
        const gateway = await connectGateway(client);
        let account_id;
        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            account_id = await getClientAccountID(contract);
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
            const identity = await newIdentity();
            const x509 = new crypto.X509Certificate(identity.credentials);
            const accountDetails = x509.toLegacyObject();
            const org = accountDetails.subject.O;
            const user = accountDetails.subject.CN;
            const docRef = db.collection('offers').doc();
            await docRef.set({
                account_id,
                from_token,
                from_value,
                to_token,
                to_value,
                org,
                user,
                created: moment().format("YYYY-MM-DD HH:mm:ss")
            });
            res.send({
                error: 0
            });
        }
    }
});

app.get('/getAllTokens', async (req, res) => {
    const client = await newGrpcConnection();

    const gateway = await connectGateway(client);

    try {
        // Get a network instance representing the channel where the smart contract is deployed.
        const network = gateway.getNetwork(channelName);

        // Get the smart contract from the network.
        const contract = network.getContract(chaincodeName);

        // Return all the current assets on the ledger.
        res.send({
            error: 0,
            data: await getAllTokens(contract)
        });

    } finally {
        gateway.close();
        client.close();
    }
});

app.get('/getAllTransfer', async (req, res) => {
    const client = await newGrpcConnection();

    const gateway = await connectGateway(client);

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
});

app.post('/deposit', async (req, res) => {
    let token = req.body.token;
    let value = req.body.value;
    let points_list = req.body.points_list;

    if (token == undefined || value == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        token = token.toString();
        value = value.toString();

        const gateway = connect({
            client,
            identity: await newIdentity(),
            signer: await newSigner(),
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

        //todo add check and check owner api from app

        try {
            const network = gateway.getNetwork(channelName);
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                data: await mint(contract, token, value, JSON.stringify(points_list))
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
})

app.get('/mint', async (req, res) => {
    let token = req.query.token;
    let value = req.query.value;

    if (token == undefined || value == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        token = token.toString();
        value = value.toString();

        const gateway = connect({
            client,
            identity: await newIdentity(),
            signer: await newSigner(),
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

        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                data: await mint(contract, token, value, "")
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

app.get('/transferAsset', async (req, res) => {
    let assetId = req.query.assetId;
    let newOwner = req.query.newOwner;

    if (assetId == undefined || newOwner == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        assetId = assetId.toString();
        newOwner = newOwner.toString();
        const gateway = await connectGateway(client);

        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                data: await transferAssetAsync(contract, assetId, newOwner)
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

app.post('/acceptOffer', async (req, res) => {
    const offer_id = req.body.offer_id;
    if (offer_id == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
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
            const account_id = doc.account_id;
            const from_value = doc.to_value;
            const from_token = doc.to_token;
            const to_value = doc.from_value;
            const to_token = doc.from_token;
            const client = await newGrpcConnection();
            const gateway = await connectGateway(client);

            try {
                // console.log(account_id, from_value, to_value, from_token, to_token);
                // Get a network instance representing the channel where the smart contract is deployed.
                const network = gateway.getNetwork(channelName);

                // Get the smart contract from the network.
                const contract = network.getContract(chaincodeName);

                // Return all the current assets on the ledger.
                res.send({
                    error: 0,
                    data: await transferBalanceAsync(contract, account_id, from_value, to_value, from_token, to_token)
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
});

app.get('/transferBalance', async (req, res) => {
    let toAddressId = req.query.toAddressId;
    let fromValue = req.query.fromValue;
    let fromToken = req.query.fromToken;
    let toValue = req.query.toValue;
    let toToken = req.query.toToken;

    if (toAddressId == undefined || fromValue == undefined || fromToken == undefined || toValue == undefined || toToken == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        toAddressId = toAddressId.toString();
        fromValue = fromValue.toString();
        fromToken = fromToken.toString();
        toValue = toValue.toString();
        toToken = toToken.toString();
        const client = await newGrpcConnection();
        const gateway = await connectGateway(client);

        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Get the smart contract from the network.
            const contract = network.getContract(chaincodeName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                data: await transferBalanceAsync(contract, toAddressId, fromValue, toValue, fromToken, toToken)
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

app.get('/getHistory', async (req, res) => {
    let token = req.query.token;

    if (token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        token = token.toString();
        const gateway = await connectGateway(client);

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
});

app.get('/getHistoryWithSource', async (req, res) => {
    let token = req.query.token;

    if (token == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        token = token.toString();
        const gateway = await connectGateway(client);

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
});

app.get('/getBlockDetails', async (req, res) => {
    let number = req.query.number;

    if (number == undefined) {
        res.send({
            error: 0,
            data: null
        });
    } else {
        const client = await newGrpcConnection();
        const gateway = await connectGateway(client);

        try {
            // Get a network instance representing the channel where the smart contract is deployed.
            const network = gateway.getNetwork(channelName);

            // Return all the current assets on the ledger.
            res.send({
                error: 0,
                // data: await getBlockDetails(network, number)
                data1: await getChainInfo(network),
                data2: await getBlockDetails(network, number.toString())
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
});

app.get('/getEncode', (req, res) => {
    res.send({
        error: 0,
        data: encodeHeader()
    });
})

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

// app.get('/getAllHistory', async (req, res) => {

//     const client = await newGrpcConnection();
//     const gateway = await connectGateway(client);

//     try {
//         // Get a network instance representing the channel where the smart contract is deployed.
//         const network = gateway.getNetwork(channelName);

//         // Get the smart contract from the network.
//         const contract = network.getContract(chaincodeName);

//         const allAsset = await getAllAssets(contract);
//         console.log("allAsset", allAsset);
//         let allHistory: any[] = [];
//         for (let i = 0 ; i < allAsset.length; i++) {
//             allHistory = allHistory.concat(await getWalletHistory(contract, allAsset[i].ID));
//         }
//         allHistory.sort((a,b) => b.Timestamp.localeCompare(a.Timestamp));

//         // Return all the current assets on the ledger.
//         res.send({
//             error: 0,
//             data: allHistory
//         });
//     } catch (error: any) {
//         console.log(error);
//         res.send({
//             error: 1,
//             errmsg: error.cause.details
//         });
//     } finally {
//         gateway.close();
//         client.close();
//     }
// });

const port = process.env.PORT || 3001

app.listen(port, () => console.log(`App listening on PORT ${port}`))

async function connectGateway(client: any): Promise<Gateway> {
    return connect({
        client,
        identity: await newIdentity(),
        signer: await newSigner(),
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
    // await contract.submitTransaction('Mint', '2000', 'token1');
    // await contract.submitTransaction('Mint', '3000', 'token2');

    console.log('*** Transaction committed successfully');
}

async function initMint(contract: Contract): Promise<void> {
    console.log('\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger');

    await contract.submitTransaction('MintToAllUser', '1000');

    console.log('*** Transaction committed successfully');
}

async function testTrans(contract: Contract, n: string): Promise<void> {
    console.log('\n--> Submit Transaction: TestTransfer, function creates the transection between user');

    await contract.submitTransaction('TestTransfer', n, '2');

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

async function getChainInfo(network: Network): Promise<any> {
    console.log('\n*** Start get getChainInfo');

    const contract = network.getContract("qscc");

    let resultBytes = await contract.evaluateTransaction("GetChainInfo", channelName);

    const blockProto = JSON.parse(JSON.stringify(fabproto6.common.BlockchainInfo.decode(resultBytes)));

    return blockProto;
}

function encodeHeader(): String {
    var sequence2 = new asn1js.Sequence({
        value: [
            new asn1js.Integer({ value: 7 }),
            new asn1js.OctetString({ valueHex: "5d819d5c5d2bf5a35185459719d594dc4f645eceb323c469b69ebf9f5f663f4a" }),
            new asn1js.OctetString({ valueHex: "f06c07e683923f59095ff1ca90229c9a1fc7a5e5920e5328883789849f39b4da" }),
        ]
    });
    return sequence2;
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

async function newGrpcConnection(): Promise<grpc.Client> {
    const tlsRootCert = await fs.readFile(tlsCertPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    return new grpc.Client(peerEndpoint, tlsCredentials, {
        'grpc.ssl_target_name_override': peerHostAlias,
    });
}

async function newIdentity(): Promise<Identity> {
    const credentials = await fs.readFile(certPath);
    return { mspId, credentials };
}

async function newSigner(): Promise<Signer> {
    const files = await fs.readdir(keyDirectoryPath);
    const keyPath = path.resolve(keyDirectoryPath, files[0]);
    const privateKeyPem = await fs.readFile(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return signers.newPrivateKeySigner(privateKey);
}