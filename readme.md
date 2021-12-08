# commit--cli

A command-line interface for [commit--blog](https://github.com/uniphil/commit--blog)


## Creating a commit --blog

If you use Git, you’ve already begun! To create a public **commit --blog** of your own, you don’t need to dive deeper into this repo. Go to https://commit--blog.com, follow the instructions there to create an account, and start picking some of your favourite commits to publish.


### Publishing commits with the CLI

Once you have an account set up, log in from the CLI with

```bash
git blog login
```

Once logged in, you can publish commits with

```bash
git blog post
```

By default it will attempt to publish the commit at the `HEAD` of whatever repository your terminal is in when you run it.

_For the moment, only repositories with a github ssh origin are supported, but more general git support is coming soon. Make sure you push your commit before trying to publish it as a post :)_

You can provide any git reference to publish a specific commit

```bash
git blog post main~2
```

To see full usage details,

```bash
git blog --help
```


## Contributing

We’re still working on this part of the README. For now, you can [check out the project’s active issues](https://github.com/uniphil/commit--cli/issues).


### Working with a local/alternate instance of the commit--blog site

Use the `COMMITBLOG_HOST` environment variable override. For example, to hack on the commit--blog dev server locally,

```bash
COMMITBLOG_HOST=http://localhost:5000 cargo run login

# or with the installed version:
COMMITBLOG_HOST=http://localhost:5000 git blog login
```


## License

[GNU Affero General Public License](./license)

