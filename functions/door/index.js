import { handle } from "../_door.js";

// /door: what the door is and a fresh knock link
export const onRequest = ctx => handle(ctx);
