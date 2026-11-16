import { Veil, VeilOptions } from '../../index';

export interface NextJsContext {
  params?: Record<string, string | string[]>;
  veil: Veil;
}

export declare function withPiiVeil<T = any>(
  handler: (req: Request, context: NextJsContext) => Promise<Response>,
  options?: VeilOptions
): (req: Request, context?: any) => Promise<Response>;
