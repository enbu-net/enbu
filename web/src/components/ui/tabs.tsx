import { Tabs as ArkTabs } from "@ark-ui/react/tabs";
import { createSlotRecipeContext } from "styled-system/jsx";
import { tabs } from "styled-system/recipes";

const { withProvider, withContext } = createSlotRecipeContext(tabs);

export const Root = withProvider(ArkTabs.Root, "root");
export const List = withContext(ArkTabs.List, "list");
export const Trigger = withContext(ArkTabs.Trigger, "trigger");
export const Content = withContext(ArkTabs.Content, "content");
export const Indicator = withContext(ArkTabs.Indicator, "indicator");
