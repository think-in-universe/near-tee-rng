import * as Joi from 'joi';

export const envVariablesValidationSchema = Joi.object({
  APP_PORT: Joi.number().default(3000),

  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),

  TEE_RNG_CONTRACT: Joi.string().required(),

  NEAR_NETWORK_ID: Joi.string().valid('mainnet', 'testnet').allow('', null),
  NEAR_NODE_URL: Joi.string().allow('', null),
}).unknown();
