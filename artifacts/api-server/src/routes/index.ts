import { Router, type IRouter } from "express";
import healthRouter from "./health";
import rolesRouter from "./roles";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/roles", rolesRouter);

export default router;
