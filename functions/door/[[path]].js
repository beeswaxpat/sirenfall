import { handle } from "../_door.js";

// /door/knock, /door/k/<id> (receipts) and the scene's claim, heard and release
export const onRequest = ctx => handle(ctx);
