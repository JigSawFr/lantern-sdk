/**
 * Requests (SPEC.md § 11) on the server's side: titles an account asks the
 * server to get. `RequestStore` is the interface a server implements over its
 * own storage; `MemoryRequestStore` keeps them in memory. LanternApp answers
 * the routes, sends the event `request` (§ 18.2) for each one made, changed
 * or withdrawn, and erases an account's with it (§ 5.7); a request is done
 * when its title comes into the library, or as the server decides
 * (`app.setRequestStatus()`).
 */

type Maybe<T> = T | Promise<T>;

/** A request's status (SPEC.md § 11). */
export type RequestStatus = "open" | "done" | "declined";
export const REQUEST_STATUSES: readonly RequestStatus[] = ["open", "done", "declined"];

/** A request as a store keeps it: the account it is of, then what the protocol shows of it. */
export interface StoredRequest {
  id: string;
  user: string;
  platform: string;
  title_id: string;
  status: RequestStatus;
  /** RFC 3339, UTC. */
  created: string;
}

/** Where LanternApp keeps requests. Every method may be async. */
export interface RequestStore {
  /** The requests of `user`, or of every account; in the order they were made. */
  requests(user?: string): Maybe<readonly StoredRequest[]>;
  add(request: StoredRequest): Maybe<void>;
  /** Changes a request's status; the request, or undefined when there is none of that id. */
  setStatus(id: string, status: RequestStatus): Maybe<StoredRequest | undefined>;
  /** Removes a request; the one removed, or undefined. */
  remove(id: string): Maybe<StoredRequest | undefined>;
  /** Every request of `user` erased (an account deleted, SPEC.md § 5.7). */
  forget(user: string): Maybe<void>;
}

/** Requests held in memory. */
export class MemoryRequestStore implements RequestStore {
  readonly #requests: StoredRequest[] = [];

  requests(user?: string): StoredRequest[] {
    return this.#requests.filter((r) => user === undefined || r.user === user).map((r) => ({ ...r }));
  }

  add(request: StoredRequest): void {
    this.#requests.push({ ...request });
  }

  setStatus(id: string, status: RequestStatus): StoredRequest | undefined {
    const found = this.#requests.find((r) => r.id === id);
    if (found === undefined) return undefined;
    found.status = status;
    return { ...found };
  }

  remove(id: string): StoredRequest | undefined {
    const at = this.#requests.findIndex((r) => r.id === id);
    if (at < 0) return undefined;
    const [gone] = this.#requests.splice(at, 1);
    return gone;
  }

  forget(user: string): void {
    for (let i = this.#requests.length - 1; i >= 0; i--)
      if (this.#requests[i]?.user === user) this.#requests.splice(i, 1);
  }
}
