import { Auth0Provider } from '@auth0/auth0-react';
import { memo } from 'react';
import { useRecoilValue } from 'recoil';

import { projectSettingsState } from 'state/project';

interface Props {
  children: JSX.Element;
}

export default memo(function AuthProvider({ children }: Props) {
  const pSettings = useRecoilValue(projectSettingsState);

  // if (pSettings?.project?.id) {
  return (
    <Auth0Provider
      domain="https://auth.daovous.xyz"
      clientId="4ZStsN96Ru4Ko1b9itlhLysyoDW9QudW"
      authorizationParams={{
        redirect_uri: `${window.location.origin}/api/auth/callback`
      }}
      useRefreshTokens={true}
      cacheLocation="localstorage"
    >
      {children}
    </Auth0Provider>
  );
  // } else {
  //   return <>{children}</>;
  // }
});
