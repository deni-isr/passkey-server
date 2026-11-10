import 'dotenv/config';
import {NextFunction, Request, Response} from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';
import jwt from 'jsonwebtoken';
import CustomError from '../../classes/CustomError';
import fetchData from '../../utils/fetchData';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import type {User, UserWithNoPassword} from '@sharedTypes/DBTypes';
import type {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import type {PasskeyUserGet} from '../../types/PasskeyTypes';

// Tarkistetaan että tarvittavat ympäristömuuttujat löytyvät
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

const expectedOrigin =
  NODE_ENV === 'development' ? `http://${RP_ID}:5173` : `https://${RP_ID}`;

// 1. Rekisteröidään käyttäjä Auth API:in ja luodaan Passkey-rekisteröintiasetukset
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
  next: NextFunction,
) => {
  try {
    // 1. Rekisteröidään käyttäjä Auth API:in
    const options: RequestInit = {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(req.body),
    };

    const userResponse = await fetchData<UserResponse>(
      `${AUTH_URL}/api/v1/users`,
      options,
    );

    // 2. Generoidaan Passkey-rekisteröintiasetukset
    const regOptions: PublicKeyCredentialCreationOptionsJSON =
      await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userName: userResponse.user.username,
        attestationType: 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      });

    // 3. Tallennetaan challenge tietokantaan
    await challengeModel.findOneAndUpdate(
      {email: userResponse.user.email},
      {email: userResponse.user.email, challenge: regOptions.challenge},
      {upsert: true, new: true},
    );

    // 4. Lisätään käyttäjä PasskeyUser-kokoelmaan
    await passkeyUserModel.create({
      userId: userResponse.user.user_id,
      email: userResponse.user.email,
      devices: [],
    });

    // 5. Lähetetään sähköposti ja asetukset asiakkaalle
    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// 2. Varmennetaan rekisteröintivastaus ja tallennetaan laite
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {email: string; registrationOptions: RegistrationResponseJSON}
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    const {email, registrationOptions} = req.body;

    // 1. Haetaan odotettu challenge tietokannasta
    const expectedChallenge = await challengeModel.findOne({email});
    if (!expectedChallenge) {
      next(new CustomError('Haastetta ei löytynyt', 404));
      return;
    }

    // 2. Varmennetaan rekisteröintivastaus
    const verification = await verifyRegistrationResponse({
      response: registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin,
      expectedRPID: RP_ID,
    });

    const {verified, registrationInfo} = verification;
    if (!verified || !registrationInfo) {
      next(new CustomError('Passkey-varmennus epäonnistui', 403));
      return;
    }

    const {credentialPublicKey, credentialID, counter} = registrationInfo;

    // 3. Tarkistetaan onko laite jo rekisteröity
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });
    if (existingDevice) {
      next(new CustomError('Laite on jo rekisteröity', 400));
      return;
    }

    // 4. Tallennetaan uusi tunnistuslaite AuthenticatorDevice-kokoelmaan
    const newDevice = new authenticatorDeviceModel({
      email,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      credentialID,
      counter,
      transports: registrationOptions.response.transports || [],
    });
    const newDeviceResult = await newDevice.save();

    // 5. Päivitetään käyttäjän laitelista tietokantaan
    const user = await passkeyUserModel.findOne({email});
    if (!user) {
      next(new CustomError('Käyttäjää ei löytynyt', 404));
      return;
    }
    user.devices.push(newDeviceResult._id);
    await user.save();

    // 6. Poistetaan käytetty challenge tietokannasta
    await challengeModel.findOneAndDelete({email});

    // 7. Haetaan ja palautetaan käyttäjän tiedot Auth API:sta
    const userResponse = await fetchData<UserResponse>(
      `${AUTH_URL}/api/v1/users/${user.userId}`,
    );

    res.json(userResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// 3. Luodaan kirjautumisasetukset (Authentication options)
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction,
) => {
  try {
    const {email} = req.body;

    // 1. Haetaan käyttäjä ja hänen laitteensa tietokannasta
    const user = (await passkeyUserModel
      .findOne({email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('Käyttäjää ei löytynyt', 404));
      return;
    }

    // 2. Generoidaan kirjautumisasetukset
    const opts = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: device.transports as AuthenticatorTransportFuture[],
      })),
      userVerification: 'preferred',
    });

    // 3. Tallennetaan haaste tietokantaan
    await challengeModel.findOneAndUpdate(
      {email},
      {email, challenge: opts.challenge},
      {upsert: true, new: true},
    );

    // 4. Lähetetään asetukset asiakkaalle
    res.json(opts);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// 4. Varmennetaan kirjautuminen ja palautetaan JWT-token
const verifyAuthentication = async (
  req: Request<
    {},
    {},
    {email: string; authResponse: AuthenticationResponseJSON}
  >,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  try {
    const {email, authResponse} = req.body;

    // 1. Haetaan odotettu challenge tietokannasta
    const expectedChallenge = await challengeModel.findOne({email});
    if (!expectedChallenge) {
      next(new CustomError('Haastetta ei löytynyt', 404));
      return;
    }

    const user = (await passkeyUserModel
      .findOne({email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('Käyttäjää ei löytynyt', 404));
      return;
    }

    const currentAuthenticator = user.devices.find(
      (device) => device.credentialID === authResponse.id,
    );

    if (!currentAuthenticator) {
      next(new CustomError('Tunnistuslaitetta ei ole rekisteröity', 400));
      return;
    }

    // 2. Varmennetaan kirjautumisvastaus
    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: currentAuthenticator.credentialID,
        credentialPublicKey: new Uint8Array(
          currentAuthenticator.credentialPublicKey,
        ),
        counter: currentAuthenticator.counter,
        transports:
          currentAuthenticator.transports as AuthenticatorTransportFuture[],
      },
    });

    const {verified, authenticationInfo} = verification;
    if (!verified) {
      next(new CustomError('Kirjautumisen varmennus epäonnistui', 403));
      return;
    }

    // 3. Päivitetään laitteen counter-arvo
    await authenticatorDeviceModel.findByIdAndUpdate(
      currentAuthenticator._id,
      {
        counter: authenticationInfo.newCounter,
      },
    );

    // 4. Poistetaan käytetty challenge tietokannasta
    await challengeModel.findOneAndDelete({email});

// 5. Haetaan käyttäjä Auth API:sta ja luodaan JWT-token
    const userResponse = await fetchData<UserWithNoPassword>(
      `${AUTH_URL}/api/v1/users/${user.userId}`,
    );

    const token = jwt.sign(
      {
        user_id: userResponse.user_id,
        level_name: userResponse.level_name,
      },
      JWT_SECRET,
    );

    res.json({
      message: 'Login successful',
      token,
      user: userResponse,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};