/* Copyright (c) 2026 NNSEC Sentinel */
/* SPDX-License-Identifier: AGPL-3.0-only */
export default function LoginPage(): JSX.Element {
  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-4 p-6">
      <h1 className="text-2xl font-semibold text-white">NNSEC Sentinel Login</h1>
      <form className="space-y-3 rounded-xl border border-white/20 bg-white/5 p-4">
        <input className="w-full rounded bg-black/40 p-2 text-white" placeholder="Email" />
        <input className="w-full rounded bg-black/40 p-2 text-white" placeholder="Password" type="password" />
        <button className="w-full rounded bg-emerald-500 p-2 font-medium text-black" type="submit">
          Sign in
        </button>
      </form>
    </main>
  );
}
