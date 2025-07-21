import { NearService } from './near.service';
import { LoggerService } from './logger.service';
import { teeRngContract } from '../configs/rng.config';
import { sleep } from '../utils/time';
import { TappdClient } from '../utils/tappd';
import { createHash } from 'crypto';

// Types matching the Rust contract structures
export interface Request {
  request_id: number;
  random_seed: Uint8Array;
  yield_index: {
    data_id: string;
  };
}

export interface Response {
  request_id: number;
  random_number: Uint8Array;
  signature: Uint8Array;
}

export class RngService {
  private logger = new LoggerService('rng');
  private isRunning = false;
  private pollingInterval = 500; // 0.5 seconds
  private tappdClient: TappdClient;

  constructor(
    private readonly nearService: NearService,
    private readonly contractId: string = teeRngContract!
  ) {
    const endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT;
    this.tappdClient = new TappdClient(endpoint);
  }

  /**
   * Start the RNG service to listen for requests
   */
  public async start(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('RNG service is already running');
      return;
    }

    this.isRunning = true;
    this.logger.info('Starting RNG service...');

    while (this.isRunning) {
      try {
        await this.processPendingRequests();
        await sleep(this.pollingInterval);
      } catch (error) {
        this.logger.error(`Error in RNG service loop: ${error}`);
        await sleep(this.pollingInterval * 2); // Wait longer on error
      }
    }
  }

  /**
   * Stop the RNG service
   */
  public stop(): void {
    this.isRunning = false;
    this.logger.info('RNG service stopped');
  }

  /**
   * Process pending requests from the contract
   */
  private async processPendingRequests(): Promise<void> {
    try {
      const pendingRequests = await this.getPendingRequests();
      
      if (pendingRequests.length === 0) {
        return;
      }

      this.logger.info(`Found ${pendingRequests.length} pending requests`);

      for (const request of pendingRequests) {
        try {
          await this.processRequest(request);
        } catch (error) {
          this.logger.error(`Error processing request ${request.request_id}: ${error}`);
        }
      }
    } catch (error) {
      this.logger.error(`Error fetching pending requests: ${error}`);
    }
  }

  /**
   * Get pending requests from the contract
   */
  private async getPendingRequests(): Promise<Request[]> {
    return this.nearService.getSigner().viewFunction({
      contractId: this.contractId,
      methodName: 'get_pending_requests',
      args: {
        from_index: 0,
        limit: 10,
      },
    });
  }

  /**
   * Process a single request
   */
  private async processRequest(request: Request): Promise<void> {
    this.logger.info(`Processing request ${request.request_id}`);

    // Generate random number using TEE entropy
    const randomSeed = request.random_seed;
    const randomNumber = await this.generateRandomNumber(randomSeed);

    // Create the message to sign: keccak256(keccak256(requestId, seed, random))
    const messageHash = this.createMessageHash(request.request_id, randomSeed, randomNumber);

    // Sign the message with the worker's private key
    const signature = await this.signMessage(messageHash);

    // Create response
    const response: Response = {
      request_id: request.request_id,
      random_number: randomNumber,
      signature: signature,
    };

    // Send response to contract
    await this.sendResponse(response);

    this.logger.info(`Successfully processed request ${request.request_id}`);
  }

  /**
   * Generate random number using TEE entropy
   */
  private async generateRandomNumber(seed: Uint8Array): Promise<Uint8Array> {
    try {
      // Use TEE entropy to generate random number
      const seedHex = Buffer.from(seed).toString('hex');
      const teeKey = await this.tappdClient.deriveKey(seedHex, seedHex);
      
      // Create hash of TEE key + seed for deterministic but random output
      const hasher = createHash('sha256');
      hasher.update(teeKey.asUint8Array(32));
      hasher.update(seed);
      
      return hasher.digest();
    } catch {
      this.logger.warn('TEE not available, falling back to crypto.randomBytes');
      // Fallback to crypto.randomBytes if TEE is not available
      const crypto = await import('crypto');
      return crypto.randomBytes(32);
    }
  }

  /**
   * Create the message hash that needs to be signed
   * keccak256(keccak256(requestId, seed, random))
   */
  private createMessageHash(requestId: number, seed: Uint8Array, random: Uint8Array): Uint8Array {
    // First hash: keccak256(requestId, seed, random)
    const firstHasher = createHash('sha3-256'); // keccak256
    firstHasher.update(Buffer.from(requestId.toString(16).padStart(16, '0'), 'hex')); // requestId as 8 bytes
    firstHasher.update(seed);
    firstHasher.update(random);
    const firstHash = firstHasher.digest();

    // Second hash: keccak256(firstHash)
    const secondHasher = createHash('sha3-256');
    secondHasher.update(firstHash);
    
    return secondHasher.digest();
  }

  /**
   * Sign a message with the worker's private key
   */
  private async signMessage(message: Uint8Array): Promise<Uint8Array> {
    const signature = await this.nearService.signMessage(message);
    return signature.signature;
  }

  /**
   * Send response to the contract
   */
  private async sendResponse(response: Response): Promise<void> {
    const signer = this.nearService.getSigner();

    await signer.functionCall({
      contractId: this.contractId,
      methodName: 'respond',
      args: {
        request_id: response.request_id,
        random_number: Array.from(response.random_number),
        signature: Array.from(response.signature),
      },
      gas: BigInt(200000000000000), // 200 Tgas
    });
  }

  /**
   * Get service status
   */
  public getStatus(): { isRunning: boolean; contractId: string } {
    return {
      isRunning: this.isRunning,
      contractId: this.contractId,
    };
  }
}
