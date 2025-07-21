import { NearService } from './services/near.service';
import { WorkerService } from './services/worker.service';
import { RngService } from './services/rng.service';
import { HttpService } from './services/http.service';

export async function app() {
  const nearService = new NearService();
  await nearService.init();

  const httpService = new HttpService(nearService);
  httpService.start();

  const workerService = new WorkerService(nearService);
  await workerService.init();

  const rngService = new RngService(nearService);
  await rngService.start();
}
