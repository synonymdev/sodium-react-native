import { Libsodium } from './libsodium';
import type { Constants } from './types';

export const constants: Constants = Libsodium.getConstants();
