import { NearService } from './near.service';
import { registerWorker, getWorker } from '../utils/worker';
import { sleep } from '../utils/time';
import { LoggerService } from './logger.service';
import { NEAR } from 'near-units';

export class WorkerService {
  public constructor(private readonly nearService: NearService) {}

  private logger = new LoggerService('worker');

  public async init(): Promise<void> {
    await this.register();
  }

  private async register() {
    const signer = this.nearService.getSigner();
    let worker = await getWorker(this.nearService, signer);
    if (!worker) {
      let balance = '0';
      while (balance === '0') {
        balance = await this.nearService.getBalance();
        if (balance !== '0') {
          this.logger.info(`The account has balance of ${NEAR.from(balance).toHuman()}.`);
          break;
        }
        this.logger.info(`Account has no balance. Waiting to be funded...`);
        await sleep(60_000);
      }
      // register worker with the public key derived from TEE
      const publicKey = this.nearService.getSignerPublicKey();
      await registerWorker(signer, publicKey);
      this.logger.info(`Worker registered`);
      worker = await getWorker(this.nearService, signer);
    }

    this.logger.info(`Worker: ${JSON.stringify(worker)}`);
  }
}
