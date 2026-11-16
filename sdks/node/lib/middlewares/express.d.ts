import { Veil, VeilOptions } from '../../index';

export interface ExpressMiddlewareOptions extends VeilOptions {
  restoreResponse?: boolean;
}

export declare function piiVeilMiddleware(
  options?: ExpressMiddlewareOptions
): (req: any, res: any, next?: (err?: any) => void) => void;
