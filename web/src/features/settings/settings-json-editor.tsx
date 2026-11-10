import { useEffect, useRef, useState } from "react";
import { Box, Flex } from "styled-system/jsx";
import { Button, Spinner, Text } from "../../components/ui";
import { m } from "../../paraglide/messages";

/**
 * Edits the settings as JSON, like VS Code's settings.json. The schema gives
 * completion, hover descriptions and inline problems; the settings screen
 * still checks the value before it saves.
 */
export function SettingsJsonEditor({
  value,
  schema,
  fontSize,
  onChange,
  onSave,
}: {
  value: string;
  schema: object;
  fontSize: number;
  onChange: (value: string) => void;
  onSave: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const onChangeRef = useRef(onChange);
  const onSaveRef = useRef(onSave);
  const initialRef = useRef({ value, schema, fontSize });
  const [loading, setLoading] = useState(true);

  onChangeRef.current = onChange;
  onSaveRef.current = onSave;

  useEffect(() => {
    if (!containerRef.current) return;
    let disposed = false;
    let cleanup = () => {};

    void Promise.all([
      import("monaco-editor"),
      import("monaco-editor/editor/editor.worker?worker"),
      import("monaco-editor/languages/features/json/json.worker?worker"),
    ])
      .then(([monaco, editorWorker, jsonWorker]) => {
        if (disposed || !containerRef.current) return;
        // The JSON language runs in its own worker, the rest in the editor worker.
        (
          globalThis as typeof globalThis & {
            MonacoEnvironment: { getWorker: (id: string, label: string) => Worker };
          }
        ).MonacoEnvironment = {
          getWorker: (_id, label) =>
            label === "json" ? new jsonWorker.default() : new editorWorker.default(),
        };
        const uri = monaco.Uri.parse("file:///enbu/settings.json");
        monaco.json.jsonDefaults.setDiagnosticsOptions({
          validate: true,
          allowComments: false,
          schemaValidation: "error",
          schemas: [
            {
              uri: "enbu://schemas/settings.json",
              fileMatch: [uri.toString()],
              schema: initialRef.current.schema,
            },
          ],
        });
        const model = monaco.editor.createModel(initialRef.current.value, "json", uri);
        const size = initialRef.current.fontSize;
        const editor = monaco.editor.create(containerRef.current, {
          model,
          theme: "vs-dark",
          automaticLayout: true,
          minimap: { enabled: false },
          fontSize: size,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          lineHeight: Math.round(size * 1.6),
          padding: { top: 14, bottom: 14 },
          scrollBeyondLastLine: false,
          tabSize: 2,
          ariaLabel: "settings.json",
        });
        const changes = model.onDidChangeContent(() => onChangeRef.current(model.getValue()));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => onSaveRef.current());
        setLoading(false);
        cleanup = () => {
          changes.dispose();
          editor.dispose();
          model.dispose();
        };
      })
      .catch((err: unknown) => {
        console.error("loading the editor failed", err);
        if (!disposed) setLoading(false);
      });

    return () => {
      disposed = true;
      cleanup();
    };
  }, []);

  return (
    <Box
      overflow="hidden"
      borderWidth="1px"
      borderColor="editor.border"
      borderRadius="lg"
      bg="editor.bg"
    >
      <Flex
        h="40px"
        align="center"
        px="3.5"
        color="editor.muted"
        bg="editor.surface"
        borderBottomWidth="1px"
        borderColor="editor.border"
      >
        <Text fontFamily="mono" fontSize="2xs" color="editor.muted">
          settings.json
        </Text>
      </Flex>
      <Box position="relative" h="360px">
        {loading && (
          <Flex
            position="absolute"
            inset="0"
            align="center"
            justify="center"
            gap="2"
            color="editor.muted"
          >
            <Spinner size="sm" />
            <Text fontSize="xs">{m.common_loading()}</Text>
          </Flex>
        )}
        <Box ref={containerRef} h="full" />
      </Box>
      <Flex
        minH="42px"
        align="center"
        justify="space-between"
        px="3"
        borderTopWidth="1px"
        borderColor="editor.border"
        bg="editor.surface"
      >
        <Text color="editor.muted" fontSize="2xs">
          Ctrl/Cmd + S
        </Text>
        <Button size="xs" colorPalette="accent" onClick={onSave}>
          {m.config_save()}
        </Button>
      </Flex>
    </Box>
  );
}
