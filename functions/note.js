import { handle } from "./_note.js";

// /note: a visitor's private note (POST only; there is no way to read one back)
export const onRequest = ctx => handle(ctx);
