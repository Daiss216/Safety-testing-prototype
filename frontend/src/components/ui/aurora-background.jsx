import { cn } from "@/lib/utils";

// Adapted from Aceternity UI's AuroraBackground for Tailwind v4 (colors are
// --color-* theme variables) and as a whole-page backdrop: the aurora layer
// is fixed to the viewport so long pages don't stretch the gradient. Dark
// variants are dropped because the app has no dark theme.
export const AuroraBackground = ({
  className,
  children,
  showRadialGradient = true,
  ...props
}) => {
  return (
    <main>
      <div
        className={cn(
          "relative flex flex-col h-[100vh] items-center justify-center bg-zinc-50 text-slate-950",
          className,
        )}
        {...props}
      >
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div
            className={cn(
              `
            [--white-gradient:repeating-linear-gradient(100deg,var(--color-white)_0%,var(--color-white)_7%,transparent_10%,transparent_12%,var(--color-white)_16%)]
            [--aurora:repeating-linear-gradient(100deg,var(--color-blue-500)_10%,var(--color-indigo-300)_15%,var(--color-blue-300)_20%,var(--color-violet-200)_25%,var(--color-blue-400)_30%)]
            [background-image:var(--white-gradient),var(--aurora)]
            [background-size:300%,_200%]
            [background-position:50%_50%,50%_50%]
            filter blur-[10px] invert
            after:content-[""] after:absolute after:inset-0 after:[background-image:var(--white-gradient),var(--aurora)]
            after:[background-size:200%,_100%]
            after:animate-aurora after:[background-attachment:fixed] after:mix-blend-difference
            pointer-events-none
            absolute -inset-[10px] opacity-50 will-change-transform`,

              showRadialGradient &&
                `[mask-image:radial-gradient(ellipse_at_100%_0%,black_10%,transparent_70%)]`,
            )}
          ></div>
        </div>
        {children}
      </div>
    </main>
  );
};
