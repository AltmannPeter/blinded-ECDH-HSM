import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CryptoInputProps {
  label: string;
  value: string;
  className?: string;
  multiline?: boolean;
  copyable?: boolean;
  testId?: string;
}

export function CryptoInput({ 
  label, 
  value, 
  className, 
  multiline = false, 
  copyable = true,
  testId 
}: CryptoInputProps) {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  return (
    <div className={cn("space-y-2", className)}>
      <Label className="text-sm font-medium">{label}</Label>
      <div className="flex gap-2">
        {multiline ? (
          <textarea
            value={value}
            readOnly
            className="flex-1 font-mono text-xs border rounded px-3 py-2 bg-muted resize-none"
            rows={3}
            data-testid={testId}
          />
        ) : (
          <Input
            value={value}
            readOnly
            className="flex-1 font-mono text-xs bg-muted"
            data-testid={testId}
          />
        )}
        {copyable && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            data-testid={`${testId}-copy`}
          >
            <Copy className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}
