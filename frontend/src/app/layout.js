import './globals.css'

export const metadata = {
  title: 'NetSentinel IDS',
  description: 'Hybrydowy system IDS z analizą LLM',
}

export default function RootLayout({ children }) {
  return (
    <html lang="pl">
      <body className="bg-slate-50 text-gray-900" suppressHydrationWarning>
        {children}
      </body>
    </html>
  )
}