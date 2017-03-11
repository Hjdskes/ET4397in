package module

type Module interface {
	Topics() []string
	Process(args []interface{})
}
