import { useEffect, useRef, useState } from "react";
import { Box, Flex } from "styled-system/jsx";
import { Button, Spinner, Text } from "./ui";
import type { TomlLanguageSession } from "../lib/toml-language-client";

export function TomlCodeEditor({
  value,
  onChange,
  onSave,
  saving,
}: {
  value: string;
  onChange: (value: string) => void;
  onSave: () => void;
  saving: boolean;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const onChangeRef = useRef(onChange);
  const onSaveRef = useRef(onSave);
  const initialValueRef = useRef(value);
  const errorCountRef = useRef(0);
  const [loading, setLoading] = useState(true);
  const [errorCount, setErrorCount] = useState(0);
  const [session, setSession] = useState<TomlLanguageSession>();

  onChangeRef.current = onChange;
  onSaveRef.current = onSave;

  useEffect(() => {
    if (!containerRef.current) return;
    let disposed = false;
    let cleanup = () => {};

    void Promise.all([
      import("monaco-editor"),
      import("monaco-editor/editor/editor.worker?worker"),
      import("../lib/toml-language-client"),
    ])
      .then(async ([monaco, workerModule, language]) => {
        if (disposed || !containerRef.current) return;
        (globalThis as typeof globalThis & { MonacoEnvironment: { getWorker: () => Worker } })
          .MonacoEnvironment = {
          getWorker: () => new workerModule.default(),
        };
        const model = monaco.editor.createModel(
          initialValueRef.current,
          "toml",
          monaco.Uri.parse("file:///workspace/enbu.toml"),
        );
        const editor = monaco.editor.create(containerRef.current, {
          model,
          theme: "vs-dark",
          automaticLayout: true,
          minimap: { enabled: false },
          fontSize: 13,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          lineHeight: 22,
          padding: { top: 14, bottom: 14 },
          scrollBeyondLastLine: false,
          tabSize: 2,
          wordWrap: "on",
          ariaLabel: "enbu.toml editor",
        });
        let fontSize = 13;
        const zoom = (delta: number) => {
          fontSize = Math.min(24, Math.max(10, fontSize + delta));
          editor.updateOptions({ fontSize, lineHeight: Math.round(fontSize * 1.7) });
        };
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Equal, () => zoom(1));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.Equal, () =>
          zoom(1),
        );
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.NumpadAdd, () => zoom(1));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Minus, () => zoom(-1));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.NumpadSubtract, () => zoom(-1));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Digit0, () => {
          fontSize = 13;
          editor.updateOptions({ fontSize: 13, lineHeight: 22 });
        });
        const changeSubscription = model.onDidChangeContent(() => onChangeRef.current(model.getValue()));
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
          if (errorCountRef.current === 0) onSaveRef.current();
        });
        const nextSession = await language.startTomlLanguageSession(monaco, model, (count) => {
          errorCountRef.current = count;
          setErrorCount(count);
        });
        if (disposed) {
          nextSession.dispose();
          editor.dispose();
          model.dispose();
          return;
        }
        setSession(nextSession);
        setLoading(false);
        cleanup = () => {
          nextSession.dispose();
          changeSubscription.dispose();
          editor.dispose();
          model.dispose();
        };
      })
      .catch(() => {
        if (!disposed) setLoading(false);
      });

    return () => {
      disposed = true;
      cleanup();
    };
  }, []);

  return (
    <Box overflow="hidden" borderWidth="1px" borderColor="editor.border" borderRadius="lg" bg="editor.bg">
      <Flex
        h="40px"
        align="center"
        justify="space-between"
        px="3.5"
        color="editor.muted"
        bg="editor.surface"
        borderBottomWidth="1px"
        borderColor="editor.border"
        fontFamily="mono"
        fontSize="2xs"
      >
        <Text fontFamily="mono" fontSize="2xs">
          enbu.toml
        </Text>
        <Flex align="center" gap="2">
          <Box aria-hidden="true" w="6px" h="6px" borderRadius="full" bg={errorCount ? "status.danger" : "status.success"} />
          <Text
            role="status"
            aria-live="polite"
            aria-atomic="true"
            color={errorCount ? "status.danger" : "editor.accent"}
            fontFamily="mono"
            fontSize="2xs"
          >
            {loading ? "Starting TOML LSP" : `TOML LSP · ${errorCount} problems`}
          </Text>
        </Flex>
      </Flex>
      <Box position="relative" h="320px">
        {loading && (
          <Flex position="absolute" inset="0" align="center" justify="center" gap="2" color="editor.muted">
            <Spinner size="sm" />
            <Text fontSize="xs">Loading editor…</Text>
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
        <Text color={errorCount ? "status.danger" : "editor.muted"} fontSize="2xs">
          {errorCount
            ? "Fix diagnostics before saving"
            : "Ctrl/Cmd + S save · Ctrl/Cmd +/− zoom · Ctrl/Cmd 0 reset"}
        </Text>
        <Flex gap="2">
          <Button size="xs" variant="ghost" color="editor.fg" disabled={!session} onClick={() => void session?.format()}>
            Format
          </Button>
          <Button size="xs" colorPalette="accent" loading={saving} disabled={errorCount > 0} onClick={onSave}>
            Save
          </Button>
        </Flex>
      </Flex>
    </Box>
  );
}
