export interface Messages {
  app: {
    name: string;
    language: string;
  };
  workspace: {
    title: string;
    current: string;
  };
  common: {
    loading: string;
    error: string;
    close: string;
  };
}
