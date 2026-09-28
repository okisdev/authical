export type User = {
  id: string;
  email: string;
  name: string;
  image: string | null;
};

export type TokenSet = {
  accessToken: string;
  refreshToken: string | null;
  idToken: string | null;
  accessTokenExpiresAt: number;
};

export type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  expires_at?: number;
};
