import express from "express";
import * as grpc from '@grpc/grpc-js';
import { connect, Contract, Identity, Signer, signers } from '@hyperledger/fabric-gateway';
import * as crypto from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';
import { TextDecoder } from 'util';

const app = express();

const channelName = envOrDefault('CHANNEL_NAME', 'mychannel');
const chaincodeName = envOrDefault('CHAINCODE_NAME', 'basic');
const mspId = envOrDefault('MSP_ID', 'Org1MSP');

// Path to crypto materials.
const cryptoPath = envOrDefault('CRYPTO_PATH', path.resolve('fabric-network', 'organizations', 'peerOrganizations', 'org1.example.com'));

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

const utf8Decoder = new TextDecoder();
// const assetId = `asset${Date.now()}`;


app.get('/', (req, res) => {
    res.send('Hello from express and typescript');
});

app.get('/init', async (req, res) => {
    const client = await newGrpcConnection();

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

        // Initialize a set of asset data on the ledger using the chaincode 'InitLedger' function.
        await initLedger(contract);
        res.send({
            error: 0,
            data: "Inital Assets done!"
        })
    } finally {
        gateway.close();
        client.close();
    }
});

app.get('/getAllAssets', async (req, res) => {
    const client = await newGrpcConnection();

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
            data: await getAllAssets(contract)
        });

    } finally {
        gateway.close();
        client.close();
    }
});

app.get('/getAsset', async (req, res) => {
    const assetId = req.query.assetId;

    if (assetId == undefined) {
        res.send({
            error: 1,
            errmsg: "assetId can not undefined."
        });
    } else {
        const client = await newGrpcConnection();

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
                data: await readAssetByID(contract, assetId.toString())
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

app.get('/createAsset', async (req, res) => {
    let assetId = req.query.assetId;
    let color = req.query.color;
    let size = req.query.size;
    let owner = req.query.owner;
    let value = req.query.value;

    if (assetId == undefined || color == undefined || size == undefined || owner == undefined || value == undefined) {
        res.send({
            error: 1,
            errmsg: "Missing some variables."
        });
    } else {
        const client = await newGrpcConnection();
        assetId = assetId.toString();
        color = color.toString();
        size = size.toString();
        owner = owner.toString();
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
                data: await createAsset(contract, assetId, color, size, owner, value)
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

const port = process.env.PORT || 3001

app.listen(port, () => console.log(`App listening on PORT ${port}`))

function envOrDefault(key: string, defaultValue: string): string {
    return process.env[key] || defaultValue;
}

async function initLedger(contract: Contract): Promise<void> {
    console.log('\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger');

    await contract.submitTransaction('InitLedger');

    console.log('*** Transaction committed successfully');
}

/**
 * Evaluate a transaction to query ledger state.
 */
async function getAllAssets(contract: Contract): Promise<any> {
    console.log('\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger');

    const resultBytes = await contract.evaluateTransaction('GetAllAssets');

    const resultJson = utf8Decoder.decode(resultBytes);
    const result = JSON.parse(resultJson);
    // console.log("Result:", result);
    return result;
}
/**
 * Submit a transaction synchronously, blocking until it has been committed to the ledger.
 */
async function createAsset(contract: Contract, assetId: string, color: string, size: string, owner: string, value: string): Promise<string> {
    console.log('\n--> Submit Transaction: CreateAsset, creates new asset with ID, Color, Size, Owner and AppraisedValue arguments');

    let asset;
    try {
        asset = await readAssetByID(contract, assetId);
    } catch (error) {
        asset = null;
    }
    
    if (asset == null) {
        await contract.submitTransaction(
            'CreateAsset',
            assetId,
            color,
            size,
            owner,
            value,
        );
    
        console.log('*** Transaction committed successfully');
        return "Transaction committed successfully";
    } else {
        return "AssetId is already exist";
    }
    
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

async function readAssetByID(contract: Contract, assetId: string): Promise<any> {
    console.log('\n--> Evaluate Transaction: ReadAsset, function returns asset attributes');

    const resultBytes = await contract.evaluateTransaction('ReadAsset', assetId);

    const resultJson = utf8Decoder.decode(resultBytes);
    const result = JSON.parse(resultJson);
    console.log('*** Result:', result);
    return result;
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