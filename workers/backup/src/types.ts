export interface Result { success: boolean; results: Record<string, unknown>[] }
export interface Statement { bind(...values: unknown[]): Statement; all(): Promise<Result> }
export interface Database { prepare(sql: string): Statement; batch(statements: Statement[]): Promise<Result[]> }
export interface ObjectBody { arrayBuffer(): Promise<ArrayBuffer>; text(): Promise<string> }
export interface Bucket {
  head(key: string): Promise<unknown | null>;
  get(key: string): Promise<ObjectBody | null>;
  put(key: string, body: Uint8Array | string, options: { onlyIf: Headers }): Promise<unknown | null>;
}
export interface Dump { sql: string; counts: Record<string, number>; paged: boolean }
