package govulners

type Error struct {
	Err       string `json:"error"`
	ErrorCode int    `json:"error_code"`
}

func (e Error) Error() string {
	return e.Err
}
