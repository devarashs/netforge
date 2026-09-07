// Package cli is a tiny dependency-free command tree for netforge.
//
// A Command is either a group (it has Sub commands) or a leaf (it has a Run
// function). Execute walks os.Args, descending through groups until it reaches
// a leaf, then hands the remaining arguments to that leaf to parse.
package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
)

// Command is one node in the command tree.
type Command struct {
	Name  string
	Short string
	Long  string
	// Run is set on leaf commands. It receives the arguments that follow the
	// command's own name and is responsible for its own flag parsing.
	Run func(args []string) error
	// Sub is set on group commands.
	Sub []*Command
}

func (c *Command) find(name string) *Command {
	for _, s := range c.Sub {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Execute dispatches args against the tree rooted at c.
func (c *Command) Execute(args []string) error {
	cur := c
	for {
		if cur.Run != nil {
			return cur.Run(args)
		}
		if len(args) == 0 || isHelp(args[0]) {
			cur.usage(os.Stdout)
			return nil
		}
		next := cur.find(args[0])
		if next == nil {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
			cur.usage(os.Stderr)
			return fmt.Errorf("unknown command %q", args[0])
		}
		cur = next
		args = args[1:]
	}
}

func isHelp(s string) bool {
	return s == "-h" || s == "--help" || s == "help"
}

func (c *Command) usage(w io.Writer) {
	if c.Long != "" {
		fmt.Fprintln(w, c.Long)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s — %s\n\n", c.Name, c.Short)
	if len(c.Sub) == 0 {
		return
	}
	subs := make([]*Command, len(c.Sub))
	copy(subs, c.Sub)
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	fmt.Fprintln(w, "Commands:")
	for _, s := range subs {
		fmt.Fprintf(w, "  %-14s %s\n", s.Name, s.Short)
	}
	fmt.Fprintf(w, "\nRun '%s <command> -h' for command-specific flags.\n", c.Name)
}
