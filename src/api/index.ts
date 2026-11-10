import express, {Request, Response} from 'express';
import {MessageResponse} from '../types/Messages';
import passkeyRouter from './routes/passkeyRoute';

const router = express.Router();

router.get<{}, MessageResponse>('/', (_req: Request, res: Response) => {
  res.json({
    message: 'api v1',
  });
});

router.use('/passkey', passkeyRouter);

export default router;
