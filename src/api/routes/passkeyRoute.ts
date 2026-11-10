import express from 'express';
import {
  authenticationOptions,
  setupPasskey,
  verifyAuthentication,
  verifyPasskey,
} from '../controllers/passkeyController';

const router = express.Router();

router.route('/setup').post(setupPasskey);
router.route('/verify').post(verifyPasskey);
router.route('/login-setup').post(authenticationOptions);
router.route('/login-verify').post(verifyAuthentication);

export default router;