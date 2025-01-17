import { provide, inject, reactive, onMounted, onUnmounted } from "vue";
import { SiweManager, siweStateStore, type SiweIdentityContextType } from "..";
import type { ActorConfig, HttpAgentOptions } from "@dfinity/agent";

const SiweIdentityProvider = Symbol("SiweIdentityProvider");

export function createSiweIdentityProvider({
  canisterId,
  httpAgentOptions,
  actorOptions,
}: {
  canisterId: string;
  httpAgentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
}) {
  const siweManager = new SiweManager(
    canisterId,
    httpAgentOptions,
    actorOptions,
  );

  const state = reactive({
    ...siweStateStore.getSnapshot().context,
    isPreparingLogin: false,
    isPrepareLoginError: false,
    isPrepareLoginSuccess: false,
    isPrepareLoginIdle: true,
    isLoggingIn: false,
    isLoginError: false,
    isLoginSuccess: false,
    isLoginIdle: true,
    prepareLogin: async () => await siweManager.prepareLogin(),
    login: async () => await siweManager.login(),
    clear: () => siweManager.clear(),
  });

  onMounted(() => {
    const subscription = siweStateStore.subscribe(({ context }) => {
      const {
        isInitializing,
        prepareLoginStatus,
        prepareLoginError,
        loginStatus,
        loginError,
        signMessageStatus,
        signMessageError,
        delegationChain,
        identity,
        identityAddress,
      } = context;

      state.isInitializing = isInitializing;
      state.prepareLoginStatus = prepareLoginStatus;
      state.isPreparingLogin = prepareLoginStatus === "preparing";
      state.isPrepareLoginError = prepareLoginStatus === "error";
      state.isPrepareLoginSuccess = prepareLoginStatus === "success";
      state.isPrepareLoginIdle = prepareLoginStatus === "idle";
      state.prepareLoginError = prepareLoginError;
      state.loginStatus = loginStatus;
      state.isLoggingIn = loginStatus === "logging-in";
      state.isLoginError = loginStatus === "error";
      state.isLoginSuccess = loginStatus === "success";
      state.isLoginIdle = loginStatus === "idle";
      state.loginError = loginError;
      state.signMessageStatus = signMessageStatus;
      state.signMessageError = signMessageError;
      state.delegationChain = delegationChain;
      state.identity = identity;
      state.identityAddress = identityAddress;
    });

    onUnmounted(() => {
      subscription.unsubscribe();
    });
  });

  provide(SiweIdentityProvider, state);
}

export function useSiwe() {
  const context = inject<SiweIdentityContextType | undefined>(
    SiweIdentityProvider,
  );
  if (!context) {
    throw new Error("useSiwe must be used within a SiweIdentityProvider");
  }
  return context;
}
