import React, { useEffect, useRef, useState } from "react"

const HASURA_ENDPOINT = import.meta.env.VITE_HASURA_ENDPOINT as string

function App() {
  const form = useRef(null)
  const [jwt, setJWT] = useState("")
  const [isLoggingIn, setIsLoggingIn] = useState(false)
  const [isSigningUp, setIsSigningUp] = useState(false)
  const [privateStuff, setPrivateStuff] = useState<any>([])

  useEffect(() => {
    if (!jwt) return
    fetchPrivateStuff().then(setPrivateStuff)
  }, [jwt])

  async function signup(email: string, password: string) {
    const req = await fetch(HASURA_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: `
          mutation Signup($email: String!, $password: String!) {
            signup(args: { email: $email, password: $password }) {
              token
            }
          }
        `,
        variables: {
          email,
          password,
        },
      }),
    })
    const res = await req.json()
    const token = res?.data?.signup?.token
    if (!token) alert("Signup failed")
    setJWT(token)
  }

  async function login(email: string, password: string) {
    const req = await fetch(HASURA_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: `
          mutation Login($email: String!, $password: String!) {
            login(args: { email: $email, password: $password }) {
              token
            }
          }
        `,
        variables: {
          email,
          password,
        },
      }),
    })
    const res = await req.json()
    const token = res?.data?.login?.token
    if (!token) alert("Login failed")
    setJWT(token)
  }

  async function fetchPrivateStuff() {
    const req = await fetch(HASURA_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: `
        query AllPrivateStuff {
          private_table_of_awesome_stuff {
            id
            something
          }
        }
        `,
      }),
    })
    const res = await req.json()
    const data = res?.data?.private_table_of_awesome_stuff
    if (!data) alert("Couldn't retrieve any records")
    return data
  }

  if (!jwt) {
    if (isSigningUp || isLoggingIn)
      return (
        <form
          ref={form}
          onSubmit={(e) => {
            e.preventDefault()
            const data = new FormData(form.current!)
            const email = data.get("email") as string
            const password = data.get("password") as string
            if (isLoggingIn) return login(email, password)
            if (isSigningUp) return signup(email, password)
          }}
        >
          <input name="email" type="email" placeholder="email" />
          <input name="password" type="password" placeholder="password" />
          <button type="submit">Submit</button>
        </form>
      )
    else
      return (
        <div>
          <p>Please sign up or log in</p>
          <button onClick={() => setIsSigningUp(true)}>
            Click here to sign up
          </button>
          <button onClick={() => setIsLoggingIn(true)}>
            Click here to log in
          </button>
        </div>
      )
  }

  return (
    <div>
      <p>Here is a list of private stuff only authenticated users can see:</p>
      <ul>
        {privateStuff?.map((it: any) => (
          <li>
            {it.id}: {it.something}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default App
