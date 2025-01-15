import React, { createContext, useContext, useEffect, useMemo } from "react";
import { SiweManager, siweStateStore, type SiweIdentityContextType } from "..";
import type { ActorConfig, HttpAgentOptions } from "@dfinity/agent";
import { useSelector } from "@xstate/store/react";
import { useAccount, useWalletClient } from "wagmi";

const SiweContext = createContext<SiweIdentityContextType | undefined>(
  undefined,
);

export function SiweIdentityProvider({
  canisterId,
  httpAgentOptions,
  actorOptions,
  children,
}: {
  canisterId: string;
  httpAgentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
  children: React.ReactNode;
}) {
  const { address } = useAccount();
  const { data: walletClient } = useWalletClient({ account: address });
  const siweManager = useMemo(
    () => new SiweManager(canisterId, httpAgentOptions, actorOptions),
    [canisterId, httpAgentOptions, actorOptions],
  );

  const state = useSelector(siweStateStore, (state) => state.context);

  useEffect(() => {
    if (!siweManager || !address || !walletClient) return;
    siweManager.setWalletClient(walletClient);
  }, [siweManager, address, walletClient]);

  return (
    <SiweContext.Provider
      value={{
        ...state,
        prepareLogin: () => siweManager.prepareLogin(),
        isPreparingLogin: state.prepareLoginStatus === "preparing",
        isPrepareLoginError: state.prepareLoginStatus === "error",
        isPrepareLoginSuccess: state.prepareLoginStatus === "success",
        isPrepareLoginIdle: state.prepareLoginStatus === "idle",
        login: () => siweManager.login(),
        isLoggingIn: state.loginStatus === "logging-in",
        isLoginError: state.loginStatus === "error",
        isLoginSuccess: state.loginStatus === "success",
        isLoginIdle: state.loginStatus === "idle",
        clear: () => siweManager.clear(),
      }}
    >
      {children}
    </SiweContext.Provider>
  );
}

export function useSiwe() {
  const context = useContext(SiweContext);
  if (!context) {
    throw new Error("useSiwe must be used within a SiweIdentityProvider");
  }
  return context;
}
